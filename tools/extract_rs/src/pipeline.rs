//! Pipeline feasibility for the two root chains.
//!
//! This module measures the image-side facts that decide which pipeline a
//! profile may select. It does not choose between them: both are reported with
//! a three-valued verdict, and the profile author records the choice.
//!
//! - `ghostlock`: the W1 -> W2 -> W3 credential chain. It is infeasible on a
//!   KDP image (the forged `init_cred` pointer is rejected at the next LSM
//!   hook), unknown when the KDP fact cannot be read.
//! - `dirtyfrag`: W1 only, then the libc++ page-cache stub into init. It is
//!   feasible only when the ESP shared-frag fix is absent, the UDP splice send
//!   path attaches pages, and `select_stack` is feasible for W1.
//!
//! The facts are recorded in the option superset and the generation log. The
//! profile carries only the chosen `pipeline`.

use std::collections::{BTreeMap, BTreeSet};

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::analysis::{Feasibility, RouteVerdict};
use crate::derive::{RelSymbols, disassemble_symbol, unique_offset_optional};
use crate::disasm::has_direct_call;
use crate::ikconfig::KernelConfig;

/// Presence of the ESP shared-frag half of upstream `f4c50a4034e6`
/// (5.10 backport `a6cb440f2`, first in v5.10.255): the `skb_has_shared_frag`
/// test in `esp_input`/`esp6_input`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EspFix {
    Present,
    Absent,
    #[default]
    Unknown,
}

/// The kernel's UDP splice-to-ESP send path.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SendPath {
    /// 6.5+: `__ip_append_data` calls `skb_splice_from_iter`.
    SkbSpliceFromIter,
    /// 5.10: `splice() -> udp_sendpage -> ip_append_page`.
    IpAppendPage,
    /// The path copies the page; DirtyFrag cannot write page cache.
    Copy,
    #[default]
    Unknown,
}

/// The measured image facts. `kdp = None` means the fact could not be read.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PipelineFacts {
    pub kdp: Option<bool>,
    pub esp_fix: EspFix,
    pub send_path: SendPath,
}

/// One pipeline's feasibility verdict, in the same shape as `routes[]`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PipelineOption {
    pub pipeline: String,
    pub verdict: String,
    pub reason: String,
}

impl PipelineOption {
    fn of(pipeline: &str, verdict: Feasibility, reason: impl Into<String>) -> Self {
        Self {
            pipeline: pipeline.to_string(),
            verdict: verdict.label().to_string(),
            reason: reason.into(),
        }
    }
}

/// Measure the image facts. The disassembly checks are skipped under
/// `--no-disasm` and reported as unknown, never as "absent".
pub fn measure(
    kernel: &[u8],
    symbols: &BTreeMap<String, BTreeSet<u64>>,
    rel_symbols: &RelSymbols,
    sorted_offsets: &[u64],
    config: Option<&KernelConfig>,
    allow_disasm: bool,
) -> PipelineFacts {
    let esp_fix = if allow_disasm {
        esp_fix(kernel, rel_symbols, sorted_offsets)
    } else {
        EspFix::Unknown
    };
    let send_path = if allow_disasm {
        send_path(kernel, rel_symbols, sorted_offsets)
    } else {
        SendPath::Unknown
    };
    PipelineFacts {
        kdp: kdp(config, symbols),
        esp_fix,
        send_path,
    }
}

/// Build the two pipeline verdicts from the measured facts and the route
/// verdicts. The order is stable: `ghostlock`, `dirtyfrag`.
pub fn verdicts(facts: &PipelineFacts, routes: &[RouteVerdict]) -> Vec<PipelineOption> {
    let ghostlock = match facts.kdp {
        Some(false) => PipelineOption::of(
            "ghostlock",
            Feasibility::Feasible,
            "KDP is not enabled",
        ),
        Some(true) => PipelineOption::of(
            "ghostlock",
            Feasibility::Infeasible,
            "KDP is enabled; the forged credential is rejected at the next LSM hook",
        ),
        None => PipelineOption::of(
            "ghostlock",
            Feasibility::Unknown,
            "KDP fact unavailable (no IKCONFIG and no security_integrity_current symbol)",
        ),
    };
    let select_stack = routes.iter().find(|route| route.route == "select_stack");
    let dirtyfrag = if facts.esp_fix != EspFix::Absent {
        PipelineOption::of(
            "dirtyfrag",
            Feasibility::Infeasible,
            match facts.esp_fix {
                EspFix::Present => "the ESP shared-frag fix is present".to_string(),
                _ => "the ESP fix level could not be measured".to_string(),
            },
        )
    } else if !matches!(
        facts.send_path,
        SendPath::SkbSpliceFromIter | SendPath::IpAppendPage
    ) {
        PipelineOption::of(
            "dirtyfrag",
            Feasibility::Infeasible,
            match facts.send_path {
                SendPath::Copy => "the UDP send path copies spliced pages".to_string(),
                _ => "the UDP send path could not be measured".to_string(),
            },
        )
    } else if !matches!(
        select_stack,
        Some(route) if route.verdict == Feasibility::Feasible
    ) {
        PipelineOption::of(
            "dirtyfrag",
            Feasibility::Infeasible,
            "select_stack is not feasible, so there is no page-free W1",
        )
    } else {
        PipelineOption::of(
            "dirtyfrag",
            Feasibility::Feasible,
            format!(
                "ESP fix absent; send path {}; select_stack feasible",
                match facts.send_path {
                    SendPath::SkbSpliceFromIter => "skb_splice_from_iter",
                    SendPath::IpAppendPage => "ip_append_page",
                    _ => "unknown",
                }
            ),
        )
    };
    vec![ghostlock, dirtyfrag]
}

/// `CONFIG_KDP=y` or a KDP-only symbol. The symbol wins over a config that
/// says otherwise; `None` when neither source is available.
fn kdp(config: Option<&KernelConfig>, symbols: &BTreeMap<String, BTreeSet<u64>>) -> Option<bool> {
    if symbols.contains_key("security_integrity_current")
        || symbols.contains_key("kdp_cred_init")
    {
        return Some(true);
    }
    config.map(|config| config.value("CONFIG_KDP") == "y")
}

/// Both `esp_input` and `esp6_input` must carry the shared-frag test for the
/// fix to be present. A function that is absent (the corresponding ESP family
/// is not built) is skipped; a function that is present but whose
/// `skb_cow_data` call cannot be found makes the answer unknown.
fn esp_fix(kernel: &[u8], rel_symbols: &RelSymbols, sorted_offsets: &[u64]) -> EspFix {
    let Some(cow) = unique_offset_optional(rel_symbols, "skb_cow_data") else {
        return EspFix::Unknown;
    };
    let mut fixed = 0u32;
    let mut vulnerable = 0u32;
    let mut unknown = 0u32;
    for name in ["esp_input", "esp6_input"] {
        let Ok(dis) = disassemble_symbol(kernel, rel_symbols, sorted_offsets, name, 0x800) else {
            continue;
        };
        match shared_frag_test(&dis, cow) {
            Some(true) => fixed += 1,
            Some(false) => vulnerable += 1,
            None => unknown += 1,
        }
    }
    if vulnerable > 0 {
        EspFix::Absent
    } else if fixed > 0 && unknown == 0 {
        EspFix::Present
    } else {
        EspFix::Unknown
    }
}

/// `Some(true)`: the bit-5 `tx_flags` test is in the window before the
/// `skb_cow_data` call. `Some(false)`: the call is present and the window has
/// no such test. `None`: no call to anchor the check.
fn shared_frag_test(dis: &[String], cow: u64) -> Option<bool> {
    let call = dis.iter().position(|line| has_direct_call(std::slice::from_ref(line), cow))?;
    let start = call.saturating_sub(24);
    Some(
        dis[start..call]
            .iter()
            .any(|line| shared_frag_test_line(line)),
    )
}

/// `skb_has_shared_frag()` is `tx_flags & SKBTX_SHARED_FRAG` (bit 5). The
/// compiler emits `tbnz`/`tbz wN, #5` or `and`/`tst wN, wN, #0x20`.
fn shared_frag_test_line(line: &str) -> bool {
    let test = Regex::new(
        r"(?i)\b(?:tbnz|tbz)\s+w\d+\s*,\s*#(?:0x)?5\b|\band\s+w\d+\s*,\s*w\d+\s*,\s*#0x20\b|\btst\s+w\d+\s*,\s*(?:w\d+\s*,\s*)?#0x20\b",
    )
    .unwrap();
    test.is_match(line)
}

/// A qualifying send path is proved by a direct call from the UDP splice
/// entry point. `Copy` is reported when the callers exist and none calls the
/// splice helper; `Unknown` when there is no caller to inspect.
fn send_path(kernel: &[u8], rel_symbols: &RelSymbols, sorted_offsets: &[u64]) -> SendPath {
    let mut caller_seen = false;
    if let Some(splice) = unique_offset_optional(rel_symbols, "skb_splice_from_iter") {
        for caller in ["__ip_append_data", "udp_sendpage", "ip_append_page"] {
            let Ok(dis) =
                disassemble_symbol(kernel, rel_symbols, sorted_offsets, caller, 0x2000)
            else {
                continue;
            };
            caller_seen = true;
            if has_direct_call(&dis, splice) {
                return SendPath::SkbSpliceFromIter;
            }
        }
    }
    if let Some(append) = unique_offset_optional(rel_symbols, "ip_append_page") {
        for caller in ["udp_sendpage", "inet_sendpage"] {
            let Ok(dis) =
                disassemble_symbol(kernel, rel_symbols, sorted_offsets, caller, 0x2000)
            else {
                continue;
            };
            caller_seen = true;
            if has_direct_call(&dis, append) {
                return SendPath::IpAppendPage;
            }
        }
    }
    if caller_seen {
        SendPath::Copy
    } else {
        SendPath::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(name: &'static str, verdict: Feasibility) -> RouteVerdict {
        RouteVerdict {
            route: name,
            verdict,
            reason: String::new(),
            numbers: BTreeMap::new(),
        }
    }

    fn facts(kdp: Option<bool>, esp_fix: EspFix, send_path: SendPath) -> PipelineFacts {
        PipelineFacts {
            kdp,
            esp_fix,
            send_path,
        }
    }

    #[test]
    fn shared_frag_test_shapes() {
        assert!(shared_frag_test_line("tbnz w8, #5, 0x1000"));
        assert!(shared_frag_test_line("tbz w9, #0x5, 0x1000"));
        assert!(shared_frag_test_line("and w8, w9, #0x20"));
        assert!(shared_frag_test_line("tst w8, #0x20"));
        assert!(shared_frag_test_line("tst w8, w9, #0x20"));
        assert!(!shared_frag_test_line("orr w8, w8, #0x20"));
        assert!(!shared_frag_test_line("tbnz w8, #6, 0x1000"));
        assert!(!shared_frag_test_line("and w8, w9, #0x21"));
    }

    #[test]
    fn kdp_blocks_ghostlock_only() {
        let routes = vec![route("select_stack", Feasibility::Feasible)];
        let verdicts = verdicts(
            &facts(Some(true), EspFix::Absent, SendPath::SkbSpliceFromIter),
            &routes,
        );
        assert_eq!(verdicts[0].pipeline, "ghostlock");
        assert_eq!(verdicts[0].verdict, "infeasible");
        assert_eq!(verdicts[1].pipeline, "dirtyfrag");
        assert_eq!(verdicts[1].verdict, "feasible");
    }

    #[test]
    fn unknown_kdp_is_not_offered() {
        let routes = vec![route("select_stack", Feasibility::Feasible)];
        let verdicts = verdicts(&facts(None, EspFix::Absent, SendPath::IpAppendPage), &routes);
        assert_eq!(verdicts[0].verdict, "unknown");
    }

    #[test]
    fn esp_fix_blocks_dirtyfrag() {
        let routes = vec![route("select_stack", Feasibility::Feasible)];
        let verdicts = verdicts(&facts(Some(false), EspFix::Present, SendPath::IpAppendPage), &routes);
        assert_eq!(verdicts[1].verdict, "infeasible");
        assert!(verdicts[1].reason.contains("ESP"));
    }

    #[test]
    fn copy_send_path_blocks_dirtyfrag() {
        let routes = vec![route("select_stack", Feasibility::Feasible)];
        let verdicts = verdicts(&facts(Some(false), EspFix::Absent, SendPath::Copy), &routes);
        assert_eq!(verdicts[1].verdict, "infeasible");
        assert!(verdicts[1].reason.contains("copies"));
    }

    #[test]
    fn dirtyfrag_requires_select_stack() {
        let routes = vec![route("select_stack", Feasibility::Infeasible)];
        let verdicts = verdicts(&facts(Some(false), EspFix::Absent, SendPath::IpAppendPage), &routes);
        assert_eq!(verdicts[1].verdict, "infeasible");
        assert!(verdicts[1].reason.contains("select_stack"));
    }

    #[test]
    fn both_feasible_are_equal_options() {
        let routes = vec![route("select_stack", Feasibility::Feasible)];
        let verdicts = verdicts(&facts(Some(false), EspFix::Absent, SendPath::SkbSpliceFromIter), &routes);
        assert_eq!(
            verdicts
                .iter()
                .map(|entry| entry.verdict.as_str())
                .collect::<Vec<_>>(),
            vec!["feasible", "feasible"]
        );
    }
}
