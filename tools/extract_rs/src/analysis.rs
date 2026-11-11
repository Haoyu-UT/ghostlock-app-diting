//! Kernel analysis report for `--analysis`: kernel family, waiter layout, the
//! primitive status and the route candidates.
//!
//! The report is read-only - it never writes offsets. The suggested route is a
//! starting point based on kernel evidence (waiter layout, pselect derivation,
//! path presence); a device gate with the fixed CPU pair still decides whether
//! a route is supported.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::btf::Btf;
use crate::derive::{
    GROUP_SOURCE_REQ_SIZE, McastWaiterGeometry, PSELECT_ROUTE_NFDS, PselectLayout, RelSymbols,
    WaiterLayout, derive_pselect_layout, derive_sigreturn_layout, multicast_copy_candidates,
    multicast_waiter_off_at,
};
use crate::error::ExtractError;
use crate::kallsyms;
use crate::symbols::{kernel_layout_verified, kernel_struct_macro};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Confidence {
    High,
    Medium,
    Low,
}

impl Confidence {
    fn label(self) -> &'static str {
        match self {
            Confidence::High => "high",
            Confidence::Medium => "medium",
            Confidence::Low => "low",
        }
    }
}

pub enum PselectOutcome {
    Derived(Box<PselectLayout>),
    Infeasible {
        message: String,
        numbers: BTreeMap<String, i64>,
    },
    Failed(String),
    NotAttempted(&'static str),
}

/// Three-valued route feasibility. Unknown is not Infeasible: a route with no
/// derivation may still be the only delivery, so the zero-feasible fallback may
/// choose it (labelled); it is never auto-selected while a Feasible route exists.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Feasibility {
    Feasible,
    Infeasible,
    Unknown,
}

impl Feasibility {
    pub fn label(self) -> &'static str {
        match self {
            Feasibility::Feasible => "feasible",
            Feasibility::Infeasible => "infeasible",
            Feasibility::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct RouteVerdict {
    pub route: &'static str,
    pub verdict: Feasibility,
    pub reason: String,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub numbers: BTreeMap<String, i64>,
}

impl RouteVerdict {
    /// A `select_stack` verdict that is feasible through the AArch32 compat
    /// carrier rather than the 64-bit route. The marker rides in `numbers` so
    /// the geometry builders and the app's label can key on it.
    pub fn is_compat_carrier(&self) -> bool {
        self.route == "select_stack"
            && self.verdict == Feasibility::Feasible
            && self.numbers.get("compat_carrier") == Some(&1)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SelectionBasis {
    /// The route's own derivation made it the single Feasible route.
    Derived,
    /// The zero-feasible frame rule nominated an Unknown route (heuristic).
    Fallback,
    /// The user forced the route with `--route`.
    Forced,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum RouteSelection {
    Chosen {
        route: &'static str,
        basis: SelectionBasis,
        reason: String,
    },
    Ambiguous {
        routes: Vec<&'static str>,
    },
    None {
        reason: String,
    },
}

pub struct PathCandidate {
    pub route: &'static str,
    /// (symbol, address) probed for this path; an address is None when absent.
    pub probes: Vec<(&'static str, Option<u64>)>,
    pub available: bool,
}

pub struct Analysis {
    pub release: Option<String>,
    pub kernel_major: Option<u32>,
    pub kernel_minor: Option<u32>,
    pub family: Option<&'static str>,
    pub family_verified: bool,
    pub phys: Option<u64>,
    pub phys_source: &'static str,
    pub waiter_fields: BTreeMap<String, u32>,
    pub waiter_size: Option<u32>,
    pub mm_struct_size: Option<u32>,
    pub primitive: Result<u64, String>,
    pub pselect: PselectOutcome,
    /// Per-route verdicts; empty for a release outside the 5.10 route family.
    pub verdicts: Vec<RouteVerdict>,
    pub paths: Vec<PathCandidate>,
    pub suggestion: Option<&'static str>,
    pub suggestion_confidence: Confidence,
    pub suggestion_reasons: Vec<String>,
}

pub struct Input<'a> {
    pub release: Option<&'a str>,
    pub kernel: &'a [u8],
    pub symbols: &'a BTreeMap<String, BTreeSet<u64>>,
    pub rel_symbols: &'a RelSymbols,
    pub sorted_offsets: &'a [u64],
    pub btf: Option<&'a Btf>,
    pub phys: Option<u64>,
    pub phys_source: &'static str,
    pub primitive: Result<u64, ExtractError>,
    pub allow_disasm: bool,
}

fn parse_major_minor(release: Option<&str>) -> (Option<u32>, Option<u32>) {
    let Some(release) = release else {
        return (None, None);
    };
    let mut parts = release.split('.');
    let major = parts.next().and_then(|part| part.parse::<u32>().ok());
    let minor = parts.next().and_then(|part| part.parse::<u32>().ok());
    (major, minor)
}

fn probe(
    symbols: &BTreeMap<String, BTreeSet<u64>>,
    exact: &str,
    fragments: &[&str],
) -> Option<u64> {
    kallsyms::find_function(symbols, exact, fragments)
}

/// Probes the three route paths the same way for `--analysis` and the
/// `--format conf` route suggestion; the only authority for the probe list.
/// The TCP path probe: the `tcp_zerocopy_receive` symbol, or, when that symbol
/// was inlined into the option handler, an inline-confirmed marker.
fn tcp_zerocopy_probe(
    symbols: &BTreeMap<String, BTreeSet<u64>>,
    kernel: &[u8],
    rel_symbols: &RelSymbols,
    sorted_offsets: &[u64],
) -> (&'static str, Option<u64>) {
    if let Some(address) = probe(symbols, "tcp_zerocopy_receive", &["zerocopy_receive"]) {
        return ("tcp_zerocopy_receive", Some(address));
    }
    if crate::derive::tcp_zerocopy_receive_inlined(kernel, rel_symbols, sorted_offsets) {
        return (
            "tcp_zerocopy_receive_inlined",
            probe(symbols, "do_tcp_getsockopt", &["do_tcp_getsockopt"]),
        );
    }
    ("tcp_zerocopy_receive", None)
}

pub fn probe_paths(
    symbols: &BTreeMap<String, BTreeSet<u64>>,
    kernel: &[u8],
    rel_symbols: &RelSymbols,
    sorted_offsets: &[u64],
) -> Vec<PathCandidate> {
    let build_path =
        |route: &'static str, probes: Vec<(&'static str, Option<u64>)>, require_all: bool| {
            let available = if require_all {
                probes.iter().all(|(_, address)| address.is_some())
            } else {
                probes.iter().any(|(_, address)| address.is_some())
            };
            PathCandidate {
                route,
                probes,
                available,
            }
        };
    let mut paths = vec![
        build_path(
            "select_stack",
            vec![
                (
                    "core_sys_select",
                    probe(symbols, "core_sys_select", &["core_sys_select"]),
                ),
                ("futex_wait", probe(symbols, "futex_wait", &["futex_wait"])),
            ],
            true,
        ),
        build_path(
            "tcp_zerocopy",
            vec![tcp_zerocopy_probe(
                symbols,
                kernel,
                rel_symbols,
                sorted_offsets,
            )],
            false,
        ),
        build_path(
            "multicast_waiter",
            vec![
                (
                    "ip_mc_msfadd",
                    probe(symbols, "ip_mc_msfadd", &["ip_mc_msfadd"]),
                ),
                (
                    "ip_mc_source",
                    probe(symbols, "ip_mc_source", &["ip_mc_source"]),
                ),
            ],
            false,
        ),
    ];
    paths.sort_by_key(|path| path.route);
    paths
}

/// The zero-feasible fallback: nominate an Unknown route from the image's own
/// path probes when no route derivation produced a feasible verdict. It never
/// reads a version family; the caller labels it a heuristic.
pub fn suggest_route(paths: &[PathCandidate]) -> (Option<&'static str>, Confidence, Vec<String>) {
    let available = |route: &str| {
        paths
            .iter()
            .any(|path| path.route == route && path.available)
    };
    suggest(&available)
}

/// The select_stack verdict is the same for every family: it is the pselect
/// derivation's own result.
fn select_stack_verdict(pselect: &PselectOutcome) -> RouteVerdict {
    match pselect {
        PselectOutcome::Derived(layout) => {
            let delta = layout.futex_waiter - layout.pselect_word0;
            let numbers = BTreeMap::from([
                ("pselect_word0".to_string(), layout.pselect_word0),
                ("futex_waiter".to_string(), layout.futex_waiter),
                ("buffer".to_string(), layout.pselect_buffer as i64),
                ("waiter_local".to_string(), layout.waiter_local as i64),
                ("delta".to_string(), delta),
                ("waiter_shift".to_string(), layout.shift as i64 - 2),
            ]);
            RouteVerdict {
                route: "select_stack",
                verdict: Feasibility::Feasible,
                reason: format!("pselect/futex geometry derived ({})", layout.chain),
                numbers,
            }
        }
        PselectOutcome::Infeasible { message, numbers } => RouteVerdict {
            route: "select_stack",
            verdict: Feasibility::Infeasible,
            reason: message.clone(),
            numbers: numbers.clone(),
        },
        PselectOutcome::Failed(message) => RouteVerdict {
            route: "select_stack",
            verdict: Feasibility::Unknown,
            reason: message.clone(),
            numbers: BTreeMap::new(),
        },
        PselectOutcome::NotAttempted(reason) => RouteVerdict {
            route: "select_stack",
            verdict: Feasibility::Unknown,
            reason: (*reason).to_string(),
            numbers: BTreeMap::new(),
        },
    }
}

/// The futex waiter depth, in the negative space the pselect layout uses. The
/// tcp relation is measured against it.
fn waiter_depth(pselect: &PselectOutcome) -> Option<i64> {
    match pselect {
        PselectOutcome::Derived(layout) => Some(layout.futex_waiter),
        PselectOutcome::Infeasible { numbers, .. } => numbers.get("futex_waiter").copied(),
        _ => None,
    }
}

/// The tcp_zerocopy verdict from the image. The route stamps its fake waiter
/// through the `getsockopt` zc local, which must sit exactly 8 bytes above the
/// futex waiter, and the copy cap must reach the last fake word (0x38). On 5.x
/// the cap is below that and the route cannot deliver; on the 6.1 train both
/// conditions hold (device-proven).
fn tcp_zerocopy_verdict(
    kernel: &[u8],
    rel_symbols: &RelSymbols,
    sorted_offsets: &[u64],
    pselect: &PselectOutcome,
    allow_disasm: bool,
) -> RouteVerdict {
    let unknown = |reason: String| RouteVerdict {
        route: "tcp_zerocopy",
        verdict: Feasibility::Unknown,
        reason,
        numbers: BTreeMap::new(),
    };
    if !allow_disasm {
        return unknown("--no-disasm".to_string());
    }
    let Some(waiter) = waiter_depth(pselect) else {
        return unknown("pselect/futex waiter depth not derived".to_string());
    };
    match crate::derive::derive_tcp_zerocopy_layout(
        kernel,
        rel_symbols,
        sorted_offsets,
        waiter,
    ) {
        Ok(layout) => {
            let numbers = BTreeMap::from([
                ("copy_cap".to_string(), layout.copy_cap as i64),
                ("zc_local".to_string(), layout.zc_local as i64),
                ("chain_sum".to_string(), layout.chain_sum as i64),
                ("zc_depth".to_string(), layout.zc_depth),
                ("waiter_depth".to_string(), layout.waiter_depth),
                ("delta".to_string(), layout.delta),
            ]);
            if layout.copy_cap < crate::derive::TCP_FAKE_WAITER_END {
                RouteVerdict {
                    route: "tcp_zerocopy",
                    verdict: Feasibility::Infeasible,
                    reason: format!(
                        "getsockopt copy cap {:#x} ends before the fake waiter words (need {:#x})",
                        layout.copy_cap,
                        crate::derive::TCP_FAKE_WAITER_END
                    ),
                    numbers,
                }
            } else if layout.delta != 0 {
                RouteVerdict {
                    route: "tcp_zerocopy",
                    verdict: Feasibility::Infeasible,
                    reason: format!(
                        "getsockopt zc local is {} bytes off the waiter relation (cap {:#x})",
                        layout.delta, layout.copy_cap
                    ),
                    numbers,
                }
            } else {
                RouteVerdict {
                    route: "tcp_zerocopy",
                    verdict: Feasibility::Feasible,
                    reason: format!(
                        "getsockopt zc local sits 8 bytes above the waiter (depth {:#x}), \
                         copy cap {:#x}",
                        -layout.zc_depth, layout.copy_cap
                    ),
                    numbers,
                }
            }
        }
        Err(err) => unknown(err.to_string()),
    }
}

fn unknown_verdict(route: &'static str, reason: impl Into<String>) -> RouteVerdict {
    RouteVerdict {
        route,
        verdict: Feasibility::Unknown,
        reason: reason.into(),
        numbers: BTreeMap::new(),
    }
}

/// Every route's verdict from this image, computed before any selection. Each
/// verdict is the route's own derivation; `release` only admits the 5.10
/// no-BTF waiter template as a labelled fallback. The `do_futex` frame rule is
/// deliberately absent here: it is only the zero-feasible fallback, so it
/// cannot pre-empt a route the derivation did not guess.
pub fn route_verdicts(
    kernel: &[u8],
    rel_symbols: &RelSymbols,
    sorted_offsets: &[u64],
    btf: Option<&Btf>,
    pselect: &PselectOutcome,
    allow_disasm: bool,
    release: Option<&str>,
) -> Vec<RouteVerdict> {
    let mut routes = vec![
        select_stack_verdict(pselect),
        multicast_verdict(kernel, rel_symbols, sorted_offsets, btf, release, allow_disasm),
        sigreturn_verdict(kernel, rel_symbols, sorted_offsets, btf, release, allow_disasm),
        tcp_zerocopy_verdict(kernel, rel_symbols, sorted_offsets, pselect, allow_disasm),
    ];
    /* The AArch32 compat carrier is the substitute for the 64-bit select route
     * when the image's own compat chain can carry the stamp where the 64-bit
     * strip cannot: the compat `_newselect` handler's fd_set buffer depth and
     * the 32-bit futex entry's strip home are both derived from this image
     * (derive_compat_carrier_layout). It is only a W1 carrier: the route still
     * needs sigreturn as its delivery fallback, so the pairing is the
     * condition. Nothing here reads the release family. */
    apply_compat_select(&mut routes, kernel, rel_symbols, sorted_offsets, btf, release);
    routes
}

/// Replace an infeasible 64-bit `select_stack` with the compat variant when
/// this image's compat chain covers it and sigreturn can deliver. A derivation
/// that cannot run leaves the verdict infeasible and says why.
fn apply_compat_select(
    routes: &mut [RouteVerdict],
    kernel: &[u8],
    rel_symbols: &RelSymbols,
    sorted_offsets: &[u64],
    btf: Option<&Btf>,
    release: Option<&str>,
) {
    let sigreturn_feasible = routes
        .iter()
        .any(|verdict| verdict.route == "sigreturn" && verdict.verdict == Feasibility::Feasible);
    if !sigreturn_feasible {
        return;
    }
    let Some(select) = routes
        .iter_mut()
        .find(|verdict| verdict.route == "select_stack" && verdict.verdict == Feasibility::Infeasible)
    else {
        return;
    };
    let kernel_major = release
        .and_then(|text| text.split('.').next())
        .and_then(|part| part.parse::<u32>().ok());
    match crate::derive::derive_compat_carrier_layout(
        kernel,
        rel_symbols,
        sorted_offsets,
        btf,
        kernel_major,
    ) {
        Ok(layout) => *select = compat_select_verdict(select, &layout),
        Err(error) => {
            select.reason = format!(
                "{}; compat carrier not derivable: {error}",
                select.reason
            );
        }
    }
}

/// Turn an infeasible 64-bit select verdict into the compat-carrier variant,
/// carrying the geometry this image's compat chain produced.
fn compat_select_verdict(
    infeasible: &RouteVerdict,
    layout: &crate::derive::CompatCarrierLayout,
) -> RouteVerdict {
    let mut numbers = infeasible.numbers.clone();
    numbers.insert("compat_carrier".to_string(), 1);
    numbers.insert("waiter_home".to_string(), layout.waiter_home as i64);
    numbers.insert(
        "select_dst_depth".to_string(),
        layout.select_dst_depth as i64,
    );
    RouteVerdict {
        route: "select_stack",
        verdict: Feasibility::Feasible,
        reason: format!(
            "AArch32 compat carrier ({}): the 64-bit route cannot cover the waiter strip \
             ({}); this image's compat chain puts the strip home at 0x{:x} under the \
             0x{:x} _newselect buffer (packed at 0x{:x})",
            layout.abi, infeasible.reason, layout.waiter_home, layout.select_dst_depth,
            layout.offset
        ),
        numbers,
    }
}

fn sigreturn_verdict(
    kernel: &[u8],
    rel_symbols: &RelSymbols,
    sorted_offsets: &[u64],
    btf: Option<&Btf>,
    release: Option<&str>,
    allow_disasm: bool,
) -> RouteVerdict {
    if !allow_disasm {
        return unknown_verdict("sigreturn", "--no-disasm");
    }
    // The 5.10 `rt_mutex_waiter` template is the only layout the extractor
    // carries for a BTF-less image; its provenance is part of the label. A
    // BTF-less non-5.10 image is Unknown, not guessed.
    let waiter_template_5_10 = matches!(release, Some(release) if crate::family::is_5_10(release));
    let waiter = match btf {
        Some(btf) => match WaiterLayout::from_btf(btf) {
            Ok(waiter) => waiter,
            Err(err) => return unknown_verdict("sigreturn", err.to_string()),
        },
        None if waiter_template_5_10 => crate::family::waiter_layout_5_10(),
        None => {
            return unknown_verdict(
                "sigreturn",
                "no BTF and no 5.10 waiter template for this image",
            );
        }
    };
    /* The route's stamp is the eleven-word compact waiter strip. A 6.6+
     * rt_waiter_node waiter is a different object; a feasible geometry there
     * would emit a block the native cannot run, so refuse and name the shape
     * (the same guard the route, the native profile load and the app carry). */
    if let Some(btf) = btf {
        match crate::layout::waiter_is_compact(btf) {
            Some(true) => {}
            Some(false) => {
                return unknown_verdict(
                    "sigreturn",
                    "the 6.6+ rt_waiter_node waiter shape is not representable by the \
                     sigreturn route's eleven-word compact stamp",
                );
            }
            None => return unknown_verdict("sigreturn", "BTF names no rt_mutex_waiter shape"),
        }
    }
    match derive_sigreturn_layout(
        kernel,
        rel_symbols,
        sorted_offsets,
        waiter.pi_tree_entry,
    ) {
        Ok(layout) => {
            let numbers = BTreeMap::from([
                ("off_sve".to_string(), layout.off_sve as i64),
                ("off_plain".to_string(), layout.off_plain as i64),
                ("strip_home".to_string(), layout.strip_home as i64),
                ("copy_dst_sve".to_string(), layout.copy_dst_sve as i64),
                (
                    "copy_dst_plain".to_string(),
                    layout.copy_dst_plain as i64,
                ),
                ("chain_sve".to_string(), layout.chain_sve as i64),
                ("chain_plain".to_string(), layout.chain_plain as i64),
            ]);
            RouteVerdict {
                route: "sigreturn",
                verdict: Feasibility::Feasible,
                reason: format!(
                    "fpsimd copy spans the strip (off_plain={:#x}, off_sve={:#x})",
                    layout.off_plain, layout.off_sve
                ),
                numbers,
            }
        }
        Err(ExtractError::Infeasible { message, numbers }) => RouteVerdict {
            route: "sigreturn",
            verdict: Feasibility::Infeasible,
            reason: message,
            numbers,
        },
        Err(err) => RouteVerdict {
            route: "sigreturn",
            verdict: Feasibility::Unknown,
            reason: err.to_string(),
            numbers: BTreeMap::new(),
        },
    }
}

fn multicast_verdict(
    kernel: &[u8],
    rel_symbols: &RelSymbols,
    sorted_offsets: &[u64],
    btf: Option<&Btf>,
    release: Option<&str>,
    allow_disasm: bool,
) -> RouteVerdict {
    if !allow_disasm {
        return unknown_verdict("multicast_waiter", "--no-disasm");
    }
    // The 5.10 `rt_mutex_waiter` template is the only layout the extractor
    // carries for a BTF-less image; its provenance is part of the label. A
    // BTF-less non-5.10 image is Unknown, not guessed.
    let waiter_template_5_10 = matches!(release, Some(release) if crate::family::is_5_10(release));
    let layout = match btf {
        Some(btf) => match WaiterLayout::from_btf(btf) {
            Ok(layout) => layout,
            Err(err) => return unknown_verdict("multicast_waiter", err.to_string()),
        },
        None if waiter_template_5_10 => crate::family::waiter_layout_5_10(),
        None => {
            return unknown_verdict(
                "multicast_waiter",
                "no BTF and no 5.10 waiter template for this image",
            );
        }
    };
    let (task, lock) = match (layout.task, layout.lock) {
        (Some(task), Some(lock)) => (task, lock),
        _ => {
            return unknown_verdict(
                "multicast_waiter",
                "BTF rt_mutex_waiter task/lock missing",
            );
        }
    };
    /* The route stamps the 5.x compact eleven-word strip. A 6.6+ image's
     * `rt_waiter_node` shape is a different object; a feasible geometry there
     * would emit a block the native cannot run, so the verdict refuses and
     * names the shape (the block is emitted only from a feasible verdict). */
    let waiter_compact = match btf {
        Some(btf) => match crate::layout::waiter_is_compact(btf) {
            Some(compact) => compact,
            None => {
                return unknown_verdict(
                    "multicast_waiter",
                    "BTF names no rt_mutex_waiter shape",
                );
            }
        },
        None if waiter_template_5_10 => true,
        None => {
            return unknown_verdict(
                "multicast_waiter",
                "no BTF and no 5.10 waiter template for this image",
            );
        }
    };
    /* The route's stamp buffer is `sizeof(struct group_source_req)`: the
     * setsockopt handler zeroes and copies exactly that buffer. Its size comes
     * from the image's own BTF where present (6.x); a BTF-less image has no
     * per-image source, so the UAPI constant is recorded as the labelled
     * fallback (`buffer_source = 1`) -- an ABI value, not a version fact.
     * Other stack copies in the same function belong to different options and
     * must not be used. */
    let route_size = match btf.and_then(|btf| btf.size("group_source_req")) {
        Some(size) => size as u64,
        None if btf.is_none() => GROUP_SOURCE_REQ_SIZE as u64,
        None => {
            return unknown_verdict(
                "multicast_waiter",
                "group_source_req size unavailable (BTF has no such type)",
            );
        }
    };
    let buffer_source = if btf.is_some() { "btf" } else { "uapi-fallback" };
    let mut candidates = match multicast_copy_candidates(kernel, rel_symbols, sorted_offsets) {
        Ok(candidates) => candidates,
        Err(err) => return unknown_verdict("multicast_waiter", err.to_string()),
    };
    candidates.retain(|(_, size)| *size == route_size);
    if candidates.is_empty() {
        return unknown_verdict(
            "multicast_waiter",
            format!(
                "group_source_req copy ({route_size:#x}) not found in \
                 ip_setsockopt/do_ip_setsockopt"
            ),
        );
    }
    let numbers_for = |size: u64, geometry: &McastWaiterGeometry| {
        BTreeMap::from([
            ("waiter_off".to_string(), geometry.waiter_off as i64),
            ("buffer_size".to_string(), size as i64),
            (
                "buffer_source".to_string(),
                if buffer_source == "btf" { 0 } else { 1 },
            ),
            ("task_offset".to_string(), task as i64),
            ("lock_offset".to_string(), lock as i64),
            (
                "window_end".to_string(),
                (geometry.waiter_off + lock + 8) as i64,
            ),
            (
                "setsockopt_depth".to_string(),
                geometry.setsockopt_depth as i64,
            ),
            ("waiter_depth".to_string(), geometry.waiter_depth as i64),
        ])
    };
    let mut feasible: Vec<(&'static str, u64, McastWaiterGeometry)> = Vec::new();
    let mut infeasible: Option<(String, BTreeMap<String, i64>)> = None;
    let mut errors: Vec<String> = Vec::new();
    for (copy_fn, size) in candidates {
        match multicast_waiter_off_at(
            kernel,
            rel_symbols,
            sorted_offsets,
            size,
            layout.pi_tree_entry,
            lock,
            copy_fn,
        ) {
            Ok(geometry) => {
                let window_end = geometry.waiter_off + lock + 8;
                if window_end <= size {
                    feasible.push((copy_fn, size, geometry));
                } else if infeasible.is_none() {
                    infeasible = Some((
                        format!(
                            "{copy_fn} copy window {size:#x} ends before the lock slot \
                             (need {window_end:#x})"
                        ),
                        numbers_for(size, &geometry),
                    ));
                }
            }
            Err(ExtractError::Infeasible { message, numbers }) => {
                if infeasible.is_none() {
                    infeasible = Some((message, numbers));
                }
            }
            Err(err) => errors.push(err.to_string()),
        }
    }
    if !waiter_compact && !feasible.is_empty() {
        /* A feasible copy window (below) would emit the route block, but the
         * route's stamp is the 5.x compact eleven-word strip. Refuse, naming
         * the shape; an infeasible window keeps its own geometry verdict. */
        return unknown_verdict(
            "multicast_waiter",
            "the 6.6+ rt_waiter_node waiter shape is not representable by the \
             multicast route's eleven-word compact stamp",
        );
    }
    if feasible.len() == 1 {
        let (copy_fn, size, geometry) = feasible.remove(0);
        return RouteVerdict {
            route: "multicast_waiter",
            verdict: Feasibility::Feasible,
            reason: format!(
                "{copy_fn} copy window {size:#x} reaches the lock slot \
                 (waiter_off=0x{:x}, buffer={buffer_source})",
                geometry.waiter_off
            ),
            numbers: numbers_for(size, &geometry),
        };
    }
    if feasible.len() > 1 {
        let sites: Vec<String> = feasible
            .iter()
            .map(|(copy_fn, size, _)| format!("{copy_fn}:{size:#x}"))
            .collect();
        return unknown_verdict(
            "multicast_waiter",
            format!(
                "ambiguous copy window: {} candidate sites ({})",
                feasible.len(),
                sites.join(", ")
            ),
        );
    }
    if let Some((message, mut numbers)) = infeasible {
        numbers.insert(
            "buffer_source".to_string(),
            if buffer_source == "btf" { 0 } else { 1 },
        );
        return RouteVerdict {
            route: "multicast_waiter",
            verdict: Feasibility::Infeasible,
            reason: message,
            numbers,
        };
    }
    unknown_verdict(
        "multicast_waiter",
        errors
            .first()
            .cloned()
            .unwrap_or_else(|| "multicast geometry unavailable".to_string()),
    )
}

/// Select a route from the verdict set. Exactly one Feasible route wins
/// without a prompt; more than one is ambiguous; zero may use the fallback
/// nomination, but only for a route that is not proven Infeasible.
pub fn select_route(
    verdicts: &[RouteVerdict],
    fallback: Option<(&'static str, String)>,
) -> RouteSelection {
    let feasible: Vec<&RouteVerdict> = verdicts
        .iter()
        .filter(|verdict| verdict.verdict == Feasibility::Feasible)
        .collect();
    match feasible.len() {
        1 => {
            let verdict = feasible[0];
            RouteSelection::Chosen {
                route: verdict.route,
                basis: SelectionBasis::Derived,
                reason: verdict.reason.clone(),
            }
        }
        0 => {
            let Some((route, hint_reason)) = fallback else {
                return RouteSelection::None {
                    reason: "no route is feasible and no fallback route was nominated".to_string(),
                };
            };
            match verdicts.iter().find(|verdict| verdict.route == route) {
                Some(verdict) if verdict.verdict != Feasibility::Infeasible => {
                    RouteSelection::Chosen {
                        route,
                        basis: SelectionBasis::Fallback,
                        reason: format!(
                            "{hint_reason}; selected as the zero-feasible fallback (heuristic)"
                        ),
                    }
                }
                Some(_) => RouteSelection::None {
                    reason: format!("the fallback route {route} is proven infeasible"),
                },
                None => RouteSelection::None {
                    reason: format!("the fallback route {route} has no verdict"),
                },
            }
        }
        _ => RouteSelection::Ambiguous {
            routes: feasible.iter().map(|verdict| verdict.route).collect(),
        },
    }
}

pub fn build(input: Input<'_>) -> Analysis {
    let (kernel_major, kernel_minor) = parse_major_minor(input.release);
    let family = kernel_struct_macro(input.release);
    let family_verified = kernel_layout_verified(input.release);

    let mut waiter_fields = BTreeMap::new();
    let mut waiter_size = None;
    let mut mm_struct_size = None;
    if let Some(btf) = input.btf {
        for field in [
            "tree",
            "tree_entry",
            "pi_tree",
            "pi_tree_entry",
            "task",
            "lock",
            "wake_state",
            "ww_ctx",
        ] {
            if let Some(offset) = btf.field("rt_mutex_waiter", field) {
                waiter_fields.insert(field.to_string(), offset);
            }
        }
        waiter_size = btf.size("rt_mutex_waiter");
        mm_struct_size = btf.size("mm_struct");
    }

    let pselect = if !input.allow_disasm {
        PselectOutcome::NotAttempted("--no-disasm")
    } else if input.btf.is_some() || kernel_major == Some(5) {
        // The 5.10 train carries no BTF; its waiter layout is the codegen
        // constant, and callers only reach the None arm for a 5.x release.
        match derive_pselect_layout(
            input.kernel,
            input.rel_symbols,
            input.sorted_offsets,
            input.btf,
            PSELECT_ROUTE_NFDS,
        ) {
            Ok(layout) => PselectOutcome::Derived(Box::new(layout)),
            Err(ExtractError::Infeasible { message, numbers }) => {
                PselectOutcome::Infeasible { message, numbers }
            }
            Err(err) => PselectOutcome::Failed(err.to_string()),
        }
    } else {
        PselectOutcome::NotAttempted("no embedded BTF")
    };

    let paths = probe_paths(
        input.symbols,
        input.kernel,
        input.rel_symbols,
        input.sorted_offsets,
    );
    let verdicts = route_verdicts(
        input.kernel,
        input.rel_symbols,
        input.sorted_offsets,
        input.btf,
        &pselect,
        input.allow_disasm,
        input.release,
    );
    /* The zero-feasible fallback: the image's own do_futex frame rule first,
     * then the path probes. Neither reads the version family. */
    let hint = if input.allow_disasm {
        crate::family::route_hint(input.kernel, input.rel_symbols, input.sorted_offsets)
    } else {
        None
    };
    let hint = hint.or_else(|| {
        let (hint_route, _, hint_reasons) = suggest_route(&paths);
        hint_route.map(|route| (route, hint_reasons.first().cloned().unwrap_or_default()))
    });
    let (suggestion, suggestion_confidence, suggestion_reasons) =
        match select_route(&verdicts, hint) {
            RouteSelection::Chosen {
                route,
                basis,
                reason,
            } => (
                Some(route),
                if basis == SelectionBasis::Derived {
                    Confidence::High
                } else {
                    Confidence::Low
                },
                vec![reason],
            ),
            RouteSelection::Ambiguous { routes } => (
                None,
                Confidence::Low,
                vec![format!(
                    "ambiguous: more than one feasible route: {}",
                    routes.join(", ")
                )],
            ),
            RouteSelection::None { reason } => (None, Confidence::Low, vec![reason]),
        };

    Analysis {
        release: input.release.map(str::to_string),
        kernel_major,
        kernel_minor,
        family,
        family_verified,
        phys: input.phys,
        phys_source: input.phys_source,
        waiter_fields,
        waiter_size,
        mm_struct_size,
        primitive: input.primitive.map_err(|err| err.to_string()),
        pselect,
        verdicts,
        paths,
        suggestion,
        suggestion_confidence,
        suggestion_reasons,
    }
}

fn suggest(available: &dyn Fn(&str) -> bool) -> (Option<&'static str>, Confidence, Vec<String>) {
    let mut reasons = Vec::new();
    if available("multicast_waiter") {
        reasons.push(
            "multicast path present; no route derivation produced a feasible verdict".to_string(),
        );
        return (Some("multicast_waiter"), Confidence::Low, reasons);
    }
    if available("tcp_zerocopy") {
        reasons.push(
            "tcp zc path present; no route derivation produced a feasible verdict".to_string(),
        );
        return (Some("tcp_zerocopy"), Confidence::Low, reasons);
    }
    reasons.push("no feasible route and no per-image fallback evidence".to_string());
    (None, Confidence::Low, reasons)
}

/// Routes whose layout is only meaningful when this image's pselect/futex
/// stack geometry was derived. A profile that selects one of these must be
/// rejected when the derivation was infeasible; every other route is
/// independent of that geometry.
pub fn route_depends_on_pselect_layout(route: &str) -> bool {
    route == "select_stack"
}

fn render_waiter(fields: &BTreeMap<String, u32>, size: Option<u32>) -> String {
    let mut parts: Vec<String> = fields
        .iter()
        .map(|(name, offset)| format!("{name}=0x{offset:x}"))
        .collect();
    if let Some(size) = size {
        parts.push(format!("size=0x{size:x}"));
    }
    if parts.is_empty() {
        "(no rt_mutex_waiter type in BTF)".to_string()
    } else {
        parts.join(" ")
    }
}

fn render_pselect(pselect: &PselectOutcome) -> String {
    match pselect {
        PselectOutcome::Derived(layout) => {
            let shift = layout.shift as i64 - 2;
            format!(
                "derived shift={shift} waiter=0x{:x} chain={}",
                layout.waiter_local, layout.chain
            )
        }
        PselectOutcome::Infeasible { message, .. } => format!("not derivable: {message}"),
        PselectOutcome::Failed(message) => format!("derivation failed: {message}"),
        PselectOutcome::NotAttempted(reason) => format!("not attempted ({reason})"),
    }
}

pub fn render(analysis: &Analysis) -> String {
    let mut lines = Vec::new();
    let field = |name: &str, value: String| format!("{name:<23} {value}");

    lines.push("== GhostLock kernel analysis ==".to_string());
    lines.push(field(
        "release",
        analysis
            .release
            .clone()
            .unwrap_or_else(|| "(none)".to_string()),
    ));
    lines.push(field(
        "kernel_major",
        match (analysis.kernel_major, analysis.kernel_minor) {
            (Some(major), Some(minor)) => format!("{major}.{minor}"),
            _ => "(unknown)".to_string(),
        },
    ));
    lines.push(field(
        "kernel_family",
        match (analysis.family, analysis.family_verified) {
            (Some(macro_name), true) => format!("{macro_name} (verified Android family)"),
            (Some(macro_name), false) => format!("{macro_name} (template only; unverified)"),
            (None, true) => "verified 5.15 android13 train".to_string(),
            (None, false) => "unverified (no family layout will be emitted)".to_string(),
        },
    ));
    lines.push(field(
        "kernel_phys_load",
        match analysis.phys {
            Some(phys) => format!("0x{phys:x} ({})", analysis.phys_source),
            None if analysis.phys_source == "unset" => {
                "unset (no xbl_config.img; pass --phys or let the runtime derive it)".to_string()
            }
            None => format!("unset ({})", analysis.phys_source),
        },
    ));
    lines.push(field(
        "rt_mutex_waiter",
        render_waiter(&analysis.waiter_fields, analysis.waiter_size),
    ));
    lines.push(field(
        "mm_struct size",
        analysis
            .mm_struct_size
            .map(|size| format!("0x{size:x}"))
            .unwrap_or_else(|| "(unavailable)".to_string()),
    ));
    lines.push(field(
        "primitive",
        match &analysis.primitive {
            Ok(remove_waiter) => format!("remove_waiter@0x{remove_waiter:x} unpatched"),
            Err(message) => format!("unavailable: {message}"),
        },
    ));
    lines.push(field("pselect chain", render_pselect(&analysis.pselect)));
    for path in &analysis.paths {
        let state = if path.available {
            "available"
        } else {
            "missing"
        };
        let probes: Vec<String> = path
            .probes
            .iter()
            .map(|(name, address)| match address {
                Some(address) => format!("{name}@0x{address:x}"),
                None => format!("{name}=absent"),
            })
            .collect();
        lines.push(field(
            &format!("path {}", path.route),
            format!("{state} ({})", probes.join(" ")),
        ));
    }
    for verdict in &analysis.verdicts {
        let numbers: Vec<String> = verdict
            .numbers
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect();
        let detail = if numbers.is_empty() {
            verdict.reason.clone()
        } else {
            format!("{} [{}]", verdict.reason, numbers.join(" "))
        };
        lines.push(field(
            &format!("route {}", verdict.route),
            format!("{} {detail}", verdict.verdict.label()),
        ));
    }
    lines.push("---------------------------------".to_string());
    lines.push(field(
        "suggested route",
        match analysis.suggestion {
            Some(route) => format!("{route} ({})", analysis.suggestion_confidence.label()),
            None => format!("none ({})", analysis.suggestion_confidence.label()),
        },
    ));
    for reason in &analysis.suggestion_reasons {
        lines.push(field("reasons", format!("- {reason}")));
    }
    lines.push(field(
        "note",
        "a device gate with the fixed CPU pair still decides whether a route is supported"
            .to_string(),
    ));
    lines.join("\n") + "\n"
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(route: &'static str, available: bool) -> PathCandidate {
        PathCandidate {
            route,
            probes: Vec::new(),
            available,
        }
    }

    #[test]
    fn path_presence_nominates_the_only_present_route() {
        let paths = vec![
            path("multicast_waiter", true),
            path("tcp_zerocopy", false),
        ];
        let (route, confidence, _) = suggest_route(&paths);
        assert_eq!(route, Some("multicast_waiter"));
        assert_eq!(confidence, Confidence::Low);
    }

    #[test]
    fn tcp_path_is_the_fallback_when_multicast_is_absent() {
        let paths = vec![
            path("multicast_waiter", false),
            path("tcp_zerocopy", true),
        ];
        let (route, _, _) = suggest_route(&paths);
        assert_eq!(route, Some("tcp_zerocopy"));
    }

    #[test]
    fn no_evidence_nominates_nothing() {
        let (route, confidence, _) = suggest_route(&[]);
        assert_eq!(route, None);
        assert_eq!(confidence, Confidence::Low);
    }

    #[test]
    fn only_select_stack_depends_on_the_pselect_layout() {
        assert!(route_depends_on_pselect_layout("select_stack"));
        assert!(!route_depends_on_pselect_layout("tcp_zerocopy"));
        assert!(!route_depends_on_pselect_layout("multicast_waiter"));
    }

    fn verdict(route: &'static str, value: Feasibility) -> RouteVerdict {
        RouteVerdict {
            route,
            verdict: value,
            reason: format!("{route} is {}", value.label()),
            numbers: BTreeMap::new(),
        }
    }

    fn compat_inputs() -> (Vec<u8>, RelSymbols, Vec<u64>) {
        (Vec::new(), RelSymbols::new(), Vec::new())
    }

    #[test]
    fn compat_select_requires_a_sigreturn_fallback() {
        let (kernel, symbols, offsets) = compat_inputs();
        let mut routes = vec![
            verdict("select_stack", Feasibility::Infeasible),
            verdict("sigreturn", Feasibility::Infeasible),
        ];
        apply_compat_select(
            &mut routes,
            &kernel,
            &symbols,
            &offsets,
            None,
            Some("5.10.81-android12-9-00001-g6cd504626bae-ab8485363"),
        );
        assert_eq!(routes[0].verdict, Feasibility::Infeasible);
        assert!(!routes[0].reason.contains("compat carrier"));
    }

    #[test]
    fn compat_select_leaves_a_derived_route_alone() {
        let (kernel, symbols, offsets) = compat_inputs();
        let mut routes = vec![
            verdict("select_stack", Feasibility::Feasible),
            verdict("sigreturn", Feasibility::Feasible),
        ];
        apply_compat_select(
            &mut routes,
            &kernel,
            &symbols,
            &offsets,
            None,
            Some("5.10.81-android12-9-00001-g6cd504626bae-ab8485363"),
        );
        assert!(!routes[0].is_compat_carrier());
    }

    #[test]
    fn compat_select_refusal_names_the_derivation_failure() {
        /* An image with no symbols cannot derive the compat chain: the verdict
         * stays infeasible and its reason says why (never a family guess). */
        let (kernel, symbols, offsets) = compat_inputs();
        let mut routes = vec![
            verdict("select_stack", Feasibility::Infeasible),
            verdict("sigreturn", Feasibility::Feasible),
        ];
        apply_compat_select(
            &mut routes,
            &kernel,
            &symbols,
            &offsets,
            None,
            Some("5.10.81-android12-9-00001-g6cd504626bae-ab8485363"),
        );
        assert_eq!(routes[0].verdict, Feasibility::Infeasible);
        assert!(
            routes[0].reason.contains("compat carrier not derivable"),
            "the refusal must be explained: {}",
            routes[0].reason
        );
    }

    #[test]
    fn one_feasible_route_is_chosen_without_a_prompt() {
        let verdicts = vec![
            verdict("select_stack", Feasibility::Feasible),
            verdict("multicast_waiter", Feasibility::Infeasible),
            verdict("sigreturn", Feasibility::Unknown),
            verdict("tcp_zerocopy", Feasibility::Unknown),
        ];
        match select_route(&verdicts, None) {
            RouteSelection::Chosen { route, basis, .. } => {
                assert_eq!(route, "select_stack");
                assert_eq!(basis, SelectionBasis::Derived);
            }
            other => panic!("unexpected selection: {other:?}"),
        }
    }

    #[test]
    fn two_feasible_routes_are_ambiguous() {
        let verdicts = vec![
            verdict("select_stack", Feasibility::Feasible),
            verdict("multicast_waiter", Feasibility::Feasible),
            verdict("sigreturn", Feasibility::Unknown),
            verdict("tcp_zerocopy", Feasibility::Unknown),
        ];
        match select_route(&verdicts, None) {
            RouteSelection::Ambiguous { routes } => {
                assert_eq!(routes, vec!["select_stack", "multicast_waiter"]);
            }
            other => panic!("unexpected selection: {other:?}"),
        }
    }

    #[test]
    fn zero_feasible_uses_the_frame_rule_for_an_unknown_route() {
        let verdicts = vec![
            verdict("select_stack", Feasibility::Infeasible),
            verdict("multicast_waiter", Feasibility::Infeasible),
            verdict("sigreturn", Feasibility::Unknown),
            verdict("tcp_zerocopy", Feasibility::Unknown),
        ];
        let hint = Some(("sigreturn", "do_futex frame 0x20".to_string()));
        match select_route(&verdicts, hint) {
            RouteSelection::Chosen { route, basis, .. } => {
                assert_eq!(route, "sigreturn");
                assert_eq!(basis, SelectionBasis::Fallback);
            }
            other => panic!("unexpected selection: {other:?}"),
        }
    }

    #[test]
    fn zero_feasible_never_selects_an_infeasible_frame_rule_route() {
        let verdicts = vec![
            verdict("select_stack", Feasibility::Infeasible),
            verdict("multicast_waiter", Feasibility::Infeasible),
            verdict("sigreturn", Feasibility::Unknown),
            verdict("tcp_zerocopy", Feasibility::Unknown),
        ];
        let hint = Some(("select_stack", "do_futex frame 0xc0".to_string()));
        assert!(matches!(
            select_route(&verdicts, hint),
            RouteSelection::None { .. }
        ));
    }

    #[test]
    fn no_feasible_route_and_no_hint_selects_nothing() {
        let verdicts = vec![verdict("select_stack", Feasibility::Unknown)];
        assert!(matches!(
            select_route(&verdicts, None),
            RouteSelection::None { .. }
        ));
    }

    #[test]
    fn the_6x_shape_asks_between_select_stack_and_tcp() {
        // The 6.1.138 image derives both the pselect layout and the tcp
        // relation, so the parse must prompt instead of silently taking the
        // suggestion.
        let verdicts = vec![
            verdict("select_stack", Feasibility::Feasible),
            verdict("multicast_waiter", Feasibility::Unknown),
            verdict("sigreturn", Feasibility::Unknown),
            verdict("tcp_zerocopy", Feasibility::Feasible),
        ];
        match select_route(&verdicts, None) {
            RouteSelection::Ambiguous { routes } => {
                assert_eq!(routes, vec!["select_stack", "tcp_zerocopy"]);
            }
            other => panic!("unexpected selection: {other:?}"),
        }
    }
}
