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
//!   path attaches pages, and a route is feasible for W1. W1 is delivered by
//!   the profile's own route, so `select_stack` is not required: `sigreturn`,
//!   `multicast_waiter` and `tcp_zerocopy` have all carried W1 on device. The
//!   page-free routes are a quality flag, not a dependency.
//!
//! The facts are recorded in the option superset and the generation log. The
//! extractor derives the default order (`dirtyfrag` first when both are
//! feasible); the profile carries that order, and the app resolves it at run
//! time before W1. The order is a policy, not an author prompt.

use std::collections::{BTreeMap, BTreeSet};

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::analysis::{Feasibility, RouteVerdict};
use crate::derive::{RelSymbols, disassemble_symbol, unique_offset_optional};
use crate::disasm::{has_call_or_tail_branch, has_direct_call};
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
    /// The effective ESP fix verdict: the guard and the send marking together.
    pub esp_fix: EspFix,
    /// The `!skb_has_shared_frag()` guard in `esp_input`/`esp6_input`.
    #[serde(default)]
    pub esp_guard: EspFix,
    /// The `SKBFL_SHARED_FRAG` marking in `__ip_append_data`/
    /// `__ip6_append_data` (upstream `f4c50a4034e6`).
    #[serde(default)]
    pub send_marking: SendMarking,
    pub send_path: SendPath,
}

/// The send half of the ESP shared-frag fix. A guard without this marking
/// never fires for a spliced page, so the in-place decrypt still happens.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SendMarking {
    Present,
    Absent,
    #[default]
    Unknown,
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
    let (esp_guard, send_marking) = if allow_disasm {
        (
            esp_guard(kernel, rel_symbols, sorted_offsets),
            send_marking(kernel, rel_symbols, sorted_offsets),
        )
    } else {
        (EspFix::Unknown, SendMarking::Unknown)
    };
    let send_path = if allow_disasm {
        send_path(kernel, rel_symbols, sorted_offsets)
    } else {
        SendPath::Unknown
    };
    PipelineFacts {
        kdp: kdp(config, symbols),
        esp_fix: effective_esp_fix(esp_guard, send_marking),
        esp_guard,
        send_marking,
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
    /* W1 is a zero write delivered by whichever middleware route the profile
     * names; the DirtyFrag stage itself never touches the futex route. Naming
     * a single route here suppressed the pipeline on the sigreturn-only and
     * multicast-only images, where W1 has been delivered on device. */
    let w1_routes: Vec<&RouteVerdict> = routes
        .iter()
        .filter(|route| route.verdict == Feasibility::Feasible)
        .collect();
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
    } else if w1_routes.is_empty() {
        PipelineOption::of(
            "dirtyfrag",
            Feasibility::Infeasible,
            "no route is feasible for W1",
        )
    } else {
        PipelineOption::of(
            "dirtyfrag",
            Feasibility::Feasible,
            format!(
                "{}; send path {}; W1 via {}",
                esp_gap(facts),
                match facts.send_path {
                    SendPath::SkbSpliceFromIter => "skb_splice_from_iter",
                    SendPath::IpAppendPage => "ip_append_page",
                    _ => "unknown",
                },
                w1_routes
                    .iter()
                    .map(|route| route.route)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )
    };
    vec![ghostlock, dirtyfrag]
}

/// The default pipeline order: `dirtyfrag` first when both are feasible (the
/// 2026-11-10 A/B measured it faster), the one feasible pipeline otherwise,
/// empty when neither is. A documented policy; a profile may carry an
/// explicit override order.
pub fn default_order(verdicts: &[PipelineOption]) -> Vec<String> {
    let feasible: Vec<&str> = verdicts
        .iter()
        .filter(|entry| entry.verdict == "feasible")
        .map(|entry| entry.pipeline.as_str())
        .collect();
    ["dirtyfrag", "ghostlock"]
        .into_iter()
        .filter(|name| feasible.contains(name))
        .map(str::to_string)
        .collect()
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
fn esp_guard(kernel: &[u8], rel_symbols: &RelSymbols, sorted_offsets: &[u64]) -> EspFix {
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

/// The effective fix: a guard without the send marking never fires, so the
/// pair is required. This is the verdict the DirtyFrag option consumes.
fn effective_esp_fix(guard: EspFix, marking: SendMarking) -> EspFix {
    match guard {
        EspFix::Absent => EspFix::Absent,
        EspFix::Unknown => EspFix::Unknown,
        EspFix::Present => match marking {
            SendMarking::Present => EspFix::Present,
            SendMarking::Absent => EspFix::Absent,
            SendMarking::Unknown => EspFix::Unknown,
        },
    }
}

/// Why the effective fix does not block DirtyFrag: names the missing half.
fn esp_gap(facts: &PipelineFacts) -> &'static str {
    match (facts.esp_guard, facts.send_marking) {
        (EspFix::Present, SendMarking::Absent) => {
            "the ESP guard is present but the send path does not mark shared frags"
        }
        (EspFix::Absent, _) => "the ESP shared-frag fix is absent",
        _ => "the ESP fix is not effective",
    }
}

/// The send half of `f4c50a4034e6`: `__ip_append_data`/`__ip6_append_data`
/// set `SKBFL_SHARED_FRAG` (bit 5 of `skb_shared_info.flags`) on a spliced
/// datagram frag. Instruction-level, like the guard: an `orr ..., #0x20`.
fn send_marking(kernel: &[u8], rel_symbols: &RelSymbols, sorted_offsets: &[u64]) -> SendMarking {
    let mut marked = 0u32;
    let mut unmarked = 0u32;
    for name in ["__ip_append_data", "__ip6_append_data"] {
        let Ok(dis) = disassemble_symbol(kernel, rel_symbols, sorted_offsets, name, 0x4000) else {
            continue;
        };
        if dis.iter().any(|line| send_mark_line(line)) {
            marked += 1;
        } else {
            unmarked += 1;
        }
    }
    if unmarked > 0 {
        SendMarking::Absent
    } else if marked > 0 {
        SendMarking::Present
    } else {
        SendMarking::Unknown
    }
}

fn send_mark_line(line: &str) -> bool {
    let mark = Regex::new(r"(?i)\borr\s+w\d+,\s*w\d+,\s*#0x20\b").unwrap();
    mark.is_match(line)
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

/// The functions the 6.5+ splice helper is called from, or could be after
/// inlining. `__ip_append_data`/`__ip6_append_data` carry the call upstream;
/// the wrappers and `udp_sendmsg` cover an LTO build that inlines the inner
/// append function. A name a kernel does not carry is skipped, so this is a
/// superset of the call sites, not a requirement.
const SPLICE_CALLERS: &[&str] = &[
    "__ip_append_data",
    "__ip6_append_data",
    "ip_append_data",
    "ip6_append_data",
    "ip_make_skb",
    "ip6_make_skb",
    "ip_push_pending_frames",
    "ip6_push_pending_frames",
    "udp_sendpage",
    "inet_sendpage",
    "ip_append_page",
    "udp_sendmsg",
];

/// The functions the 5.10 page path is called from. `udp_sendpage` is the
/// measured caller; the rest cover a vendor shape that moved the call.
const APPEND_PAGE_CALLERS: &[&str] = &["udp_sendpage", "inet_sendpage", "udp_sendmsg"];

/// A qualifying send path is proved by a call or tail branch from the UDP
/// splice entry point. `Copy` is reported only when every page-attaching
/// candidate was inspected and none calls the helper; `Unknown` when a
/// candidate exists but has no caller to inspect — an unexamined path is not
/// evidence that the page is copied.
fn send_path(kernel: &[u8], rel_symbols: &RelSymbols, sorted_offsets: &[u64]) -> SendPath {
    let mut inspected = 0u32;
    let mut unexamined = 0u32;
    for (symbol, callers, path) in [
        (
            "skb_splice_from_iter",
            SPLICE_CALLERS,
            SendPath::SkbSpliceFromIter,
        ),
        ("ip_append_page", APPEND_PAGE_CALLERS, SendPath::IpAppendPage),
    ] {
        let Some(target) = unique_offset_optional(rel_symbols, symbol) else {
            continue;
        };
        let mut caller_seen = false;
        for caller in callers {
            let Ok(dis) = disassemble_symbol(kernel, rel_symbols, sorted_offsets, caller, 0x2000)
            else {
                continue;
            };
            caller_seen = true;
            if has_call_or_tail_branch(&dis, target) {
                return path;
            }
        }
        if caller_seen {
            inspected += 1;
        } else {
            unexamined += 1;
        }
    }
    if inspected > 0 && unexamined == 0 {
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
        let (esp_guard, send_marking) = match esp_fix {
            EspFix::Present => (EspFix::Present, SendMarking::Present),
            EspFix::Absent => (EspFix::Absent, SendMarking::Unknown),
            EspFix::Unknown => (EspFix::Unknown, SendMarking::Unknown),
        };
        PipelineFacts {
            kdp,
            esp_fix,
            esp_guard,
            send_marking,
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
    fn default_order_prefers_dirtyfrag_and_lists_only_feasible() {
        let routes = vec![route("select_stack", Feasibility::Feasible)];
        let both = verdicts(
            &facts(Some(false), EspFix::Absent, SendPath::IpAppendPage),
            &routes,
        );
        assert_eq!(default_order(&both), vec!["dirtyfrag", "ghostlock"]);
        let kdp = verdicts(&facts(Some(true), EspFix::Absent, SendPath::IpAppendPage), &routes);
        assert_eq!(default_order(&kdp), vec!["dirtyfrag"]);
        let copy = verdicts(&facts(Some(false), EspFix::Absent, SendPath::Copy), &routes);
        assert_eq!(default_order(&copy), vec!["ghostlock"]);
        let fixed = verdicts(&facts(Some(false), EspFix::Present, SendPath::IpAppendPage), &routes);
        assert_eq!(default_order(&fixed), vec!["ghostlock"]);
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
    fn send_mark_line_shapes() {
        assert!(send_mark_line("orr w8, w8, #0x20"));
        assert!(!send_mark_line("orr w8, w8, #0x21"));
        assert!(!send_mark_line("and w8, w9, #0x20"));
        assert!(!send_mark_line("tst w8, #0x20"));
    }

    #[test]
    fn effective_fix_requires_both_halves() {
        assert_eq!(
            effective_esp_fix(EspFix::Present, SendMarking::Present),
            EspFix::Present
        );
        assert_eq!(
            effective_esp_fix(EspFix::Present, SendMarking::Absent),
            EspFix::Absent
        );
        assert_eq!(
            effective_esp_fix(EspFix::Absent, SendMarking::Present),
            EspFix::Absent
        );
        assert_eq!(
            effective_esp_fix(EspFix::Unknown, SendMarking::Present),
            EspFix::Unknown
        );
    }

    #[test]
    fn a_guard_without_the_send_marking_is_ineffective() {
        /* The guard is present but __ip_append_data never sets the flag, so
         * the guard never fires and the in-place decrypt still happens: the
         * DirtyFrag option stays feasible and names the missing half. */
        let mut f = facts(Some(false), EspFix::Absent, SendPath::IpAppendPage);
        f.esp_guard = EspFix::Present;
        f.send_marking = SendMarking::Absent;
        f.esp_fix = effective_esp_fix(f.esp_guard, f.send_marking);
        let routes = vec![route("select_stack", Feasibility::Feasible)];
        let verdicts = verdicts(&f, &routes);
        assert_eq!(verdicts[1].pipeline, "dirtyfrag");
        assert_eq!(verdicts[1].verdict, "feasible");
        assert!(verdicts[1].reason.contains("does not mark"));
    }

    #[test]
    fn copy_send_path_blocks_dirtyfrag() {
        let routes = vec![route("select_stack", Feasibility::Feasible)];
        let verdicts = verdicts(&facts(Some(false), EspFix::Absent, SendPath::Copy), &routes);
        assert_eq!(verdicts[1].verdict, "infeasible");
        assert!(verdicts[1].reason.contains("copies"));
    }

    #[test]
    fn a_feasible_w1_route_is_enough() {
        /* The 5.10.81 shape that exposed the false dependency: select_stack,
         * multicast and tcp out of band, sigreturn feasible, the ESP fix
         * absent, ip_append_page. The profile's sigreturn route delivers W1
         * (it carried the whole chain on the era rig), so DirtyFrag is
         * feasible and the reason names the route. */
        let routes = vec![
            route("select_stack", Feasibility::Infeasible),
            route("multicast_waiter", Feasibility::Infeasible),
            route("sigreturn", Feasibility::Feasible),
            route("tcp_zerocopy", Feasibility::Infeasible),
        ];
        let verdicts = verdicts(
            &facts(Some(false), EspFix::Absent, SendPath::IpAppendPage),
            &routes,
        );
        assert_eq!(verdicts[1].pipeline, "dirtyfrag");
        assert_eq!(verdicts[1].verdict, "feasible");
        assert!(verdicts[1].reason.contains("sigreturn"));
        assert!(!verdicts[1].reason.contains("select_stack"));
    }

    #[test]
    fn the_page_based_tcp_route_alone_carries_w1() {
        /* tcp_zerocopy is page-based, not page-free; W1 is a zero write and
         * the route's crafted page lock performs it (measured on the 6.1
         * POCO's page-based control). A profile that selects it must still
         * get the DirtyFrag option. */
        let routes = vec![
            route("select_stack", Feasibility::Infeasible),
            route("multicast_waiter", Feasibility::Infeasible),
            route("sigreturn", Feasibility::Infeasible),
            route("tcp_zerocopy", Feasibility::Feasible),
        ];
        let verdicts = verdicts(
            &facts(Some(false), EspFix::Absent, SendPath::IpAppendPage),
            &routes,
        );
        assert_eq!(verdicts[1].verdict, "feasible");
        assert!(verdicts[1].reason.contains("tcp_zerocopy"));
    }

    #[test]
    fn an_unknown_w1_route_is_not_a_vehicle() {
        /* A route whose verdict is unknown was not measured; it cannot
         * stand in for a feasible W1 vehicle. */
        let routes = vec![
            route("select_stack", Feasibility::Unknown),
            route("sigreturn", Feasibility::Infeasible),
        ];
        let verdicts = verdicts(
            &facts(Some(false), EspFix::Absent, SendPath::IpAppendPage),
            &routes,
        );
        assert_eq!(verdicts[1].verdict, "infeasible");
        assert!(verdicts[1].reason.contains("no route"));
    }

    #[test]
    fn an_unmeasured_send_path_is_not_a_proven_copy() {
        /* --no-disasm leaves the fact unknown. The verdict stays
         * conservative (infeasible), and the reason says it was not
         * measured rather than claiming the path copies. */
        let routes = vec![route("select_stack", Feasibility::Feasible)];
        let verdicts = verdicts(&facts(Some(false), EspFix::Absent, SendPath::Unknown), &routes);
        assert_eq!(verdicts[1].verdict, "infeasible");
        assert!(verdicts[1].reason.contains("could not be measured"));
    }

    #[test]
    fn without_disassembly_every_send_fact_is_unknown_not_copy() {
        /* The measure entry point under --no-disasm: nothing is reported as
         * absent or copied, and the verdict refuses with "not measured". */
        let symbols = BTreeMap::new();
        let rel = RelSymbols::new();
        let measured = measure(&[], &symbols, &rel, &[], None, false);
        assert_eq!(measured.send_path, SendPath::Unknown);
        assert_eq!(measured.esp_fix, EspFix::Unknown);
        assert_eq!(measured.kdp, None);
        let verdicts = verdicts(&measured, &[]);
        assert_eq!(verdicts[1].verdict, "infeasible");
        assert!(verdicts[1].reason.contains("could not be measured"));
    }

    #[test]
    fn no_w1_route_blocks_dirtyfrag() {
        let routes = vec![
            route("select_stack", Feasibility::Infeasible),
            route("sigreturn", Feasibility::Infeasible),
        ];
        let verdicts = verdicts(
            &facts(Some(false), EspFix::Absent, SendPath::IpAppendPage),
            &routes,
        );
        assert_eq!(verdicts[1].verdict, "infeasible");
        assert!(verdicts[1].reason.contains("no route"));
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

