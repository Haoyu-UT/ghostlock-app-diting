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
    MULTICAST_5X_BUFFER_SIZE, PSELECT_ROUTE_NFDS, PselectLayout, RelSymbols, WaiterLayout,
    derive_pselect_layout, derive_sigreturn_layout, multicast_waiter_off,
};
use crate::error::ExtractError;
use crate::family::{WAITER_LOCK, WAITER_TASK};
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

/// The route a profile should select from kernel evidence alone. Shared by the
/// `--analysis` report and the `--format conf` default, so both agree.
pub fn suggest_route(
    pselect_derived: bool,
    paths: &[PathCandidate],
    release: Option<&str>,
) -> (Option<&'static str>, Confidence, Vec<String>) {
    let (major, minor) = parse_major_minor(release);
    let family = kernel_struct_macro(release).filter(|_| kernel_layout_verified(release));
    let available = |route: &str| {
        paths
            .iter()
            .any(|path| path.route == route && path.available)
    };
    suggest(pselect_derived, &available, family, major, minor)
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

/// Every 5.10 route's verdict, computed before any selection. The `do_futex`
/// frame rule is deliberately absent here: it is only the zero-feasible
/// fallback, so it cannot pre-empt a route the derivation did not guess.
pub fn route_verdicts_5_10(
    kernel: &[u8],
    rel_symbols: &RelSymbols,
    sorted_offsets: &[u64],
    btf: Option<&Btf>,
    pselect: &PselectOutcome,
    allow_disasm: bool,
) -> Vec<RouteVerdict> {
    let mut verdicts = Vec::with_capacity(4);
    verdicts.push(select_stack_verdict(pselect));
    if allow_disasm {
        verdicts.push(multicast_verdict_5_10(
            kernel,
            rel_symbols,
            sorted_offsets,
            btf,
        ));
    } else {
        verdicts.push(RouteVerdict {
            route: "multicast_waiter",
            verdict: Feasibility::Unknown,
            reason: "--no-disasm".to_string(),
            numbers: BTreeMap::new(),
        });
    }
    if allow_disasm {
        verdicts.push(sigreturn_verdict_5_10(
            kernel,
            rel_symbols,
            sorted_offsets,
            btf,
        ));
    } else {
        verdicts.push(RouteVerdict {
            route: "sigreturn",
            verdict: Feasibility::Unknown,
            reason: "--no-disasm".to_string(),
            numbers: BTreeMap::new(),
        });
    }
    verdicts.push(tcp_zerocopy_verdict(
        kernel,
        rel_symbols,
        sorted_offsets,
        pselect,
        allow_disasm,
    ));
    verdicts
}

/// Every route's verdict for families without the 5.10 model (the 6.x train):
/// the pselect-derived select_stack, the derived tcp_zerocopy, and multicast /
/// sigreturn unknown until they get their own derivation.
pub fn route_verdicts_other(
    kernel: &[u8],
    rel_symbols: &RelSymbols,
    sorted_offsets: &[u64],
    pselect: &PselectOutcome,
    allow_disasm: bool,
) -> Vec<RouteVerdict> {
    let unknown = |route: &'static str, reason: &str| RouteVerdict {
        route,
        verdict: Feasibility::Unknown,
        reason: reason.to_string(),
        numbers: BTreeMap::new(),
    };
    vec![
        select_stack_verdict(pselect),
        unknown(
            "multicast_waiter",
            "no non-5.10 multicast geometry derivation",
        ),
        unknown("sigreturn", "no non-5.10 sigreturn geometry derivation"),
        tcp_zerocopy_verdict(
            kernel,
            rel_symbols,
            sorted_offsets,
            pselect,
            allow_disasm,
        ),
    ]
}

/// Dispatch on the release major: the 5.x line keeps its own model, every
/// other family uses the generic one.
pub fn route_verdicts(
    kernel: &[u8],
    rel_symbols: &RelSymbols,
    sorted_offsets: &[u64],
    btf: Option<&Btf>,
    pselect: &PselectOutcome,
    allow_disasm: bool,
    release_major: Option<u32>,
) -> Vec<RouteVerdict> {
    if release_major == Some(5) {
        route_verdicts_5_10(kernel, rel_symbols, sorted_offsets, btf, pselect, allow_disasm)
    } else {
        route_verdicts_other(kernel, rel_symbols, sorted_offsets, pselect, allow_disasm)
    }
}

fn sigreturn_verdict_5_10(
    kernel: &[u8],
    rel_symbols: &RelSymbols,
    sorted_offsets: &[u64],
    btf: Option<&Btf>,
) -> RouteVerdict {
    let waiter = match btf {
        Some(btf) => WaiterLayout::from_btf(btf),
        None => Ok(crate::family::waiter_layout_5_10()),
    };
    let waiter = match waiter {
        Ok(waiter) => waiter,
        Err(err) => {
            return RouteVerdict {
                route: "sigreturn",
                verdict: Feasibility::Unknown,
                reason: err.to_string(),
                numbers: BTreeMap::new(),
            };
        }
    };
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

fn multicast_verdict_5_10(
    kernel: &[u8],
    rel_symbols: &RelSymbols,
    sorted_offsets: &[u64],
    btf: Option<&Btf>,
) -> RouteVerdict {
    let waiter = match btf {
        Some(btf) => WaiterLayout::from_btf(btf),
        None => Ok(crate::family::waiter_layout_5_10()),
    };
    let layout = match waiter {
        Ok(layout) => layout,
        Err(err) => {
            return RouteVerdict {
                route: "multicast_waiter",
                verdict: Feasibility::Unknown,
                reason: err.to_string(),
                numbers: BTreeMap::new(),
            };
        }
    };
    let (task, lock) = match (layout.task, layout.lock) {
        (Some(task), Some(lock)) => (task, lock),
        // The fallback is the 5.10 codegen layout, valid only when the image
        // carried no BTF at all; a BTF image missing these fields is Unknown.
        _ if btf.is_none() => (WAITER_TASK, WAITER_LOCK),
        _ => {
            return RouteVerdict {
                route: "multicast_waiter",
                verdict: Feasibility::Unknown,
                reason: "BTF rt_mutex_waiter task/lock missing".to_string(),
                numbers: BTreeMap::new(),
            };
        }
    };
    match multicast_waiter_off(
        kernel,
        rel_symbols,
        sorted_offsets,
        MULTICAST_5X_BUFFER_SIZE as u64,
        layout.pi_tree_entry,
        lock,
    ) {
        Ok(geometry) => {
            let window_end = geometry.waiter_off + lock + 8;
            let numbers = BTreeMap::from([
                ("waiter_off".to_string(), geometry.waiter_off as i64),
                ("buffer_size".to_string(), MULTICAST_5X_BUFFER_SIZE),
                ("task_offset".to_string(), task as i64),
                ("lock_offset".to_string(), lock as i64),
                ("window_end".to_string(), window_end as i64),
                (
                    "setsockopt_depth".to_string(),
                    geometry.setsockopt_depth as i64,
                ),
                ("waiter_depth".to_string(), geometry.waiter_depth as i64),
            ]);
            RouteVerdict {
                route: "multicast_waiter",
                verdict: Feasibility::Feasible,
                reason: format!(
                    "copy window reaches the lock slot \
                     (waiter_off=0x{:x}, buffer=0x{:x})",
                    geometry.waiter_off, MULTICAST_5X_BUFFER_SIZE
                ),
                numbers,
            }
        }
        Err(ExtractError::Infeasible { message, numbers }) => RouteVerdict {
            route: "multicast_waiter",
            verdict: Feasibility::Infeasible,
            reason: message,
            numbers,
        },
        Err(err) => RouteVerdict {
            route: "multicast_waiter",
            verdict: Feasibility::Unknown,
            reason: err.to_string(),
            numbers: BTreeMap::new(),
        },
    }
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
        kernel_major,
    );
    let hint = if kernel_major == Some(5) {
        if input.allow_disasm {
            input.release.and_then(|release| {
                crate::family::route_hint(
                    input.kernel,
                    input.rel_symbols,
                    input.sorted_offsets,
                    release,
                )
            })
        } else {
            None
        }
    } else {
        let pselect_derived = matches!(pselect, PselectOutcome::Derived(_));
        let (hint_route, _, hint_reasons) =
            suggest_route(pselect_derived, &paths, input.release);
        hint_route.map(|route| (route, hint_reasons.first().cloned().unwrap_or_default()))
    };
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

fn suggest(
    pselect_derived: bool,
    available: &dyn Fn(&str) -> bool,
    family: Option<&'static str>,
    major: Option<u32>,
    minor: Option<u32>,
) -> (Option<&'static str>, Confidence, Vec<String>) {
    let mut reasons = Vec::new();
    if pselect_derived {
        reasons.push("pselect/futex waiter layout derived from the kernel".to_string());
        return (Some("select_stack"), Confidence::High, reasons);
    }
    if major == Some(5) && available("multicast_waiter") {
        reasons.push("5.x kernel with the multicast path present".to_string());
        reasons.push("pselect route not derivable on this layout".to_string());
        return (Some("multicast_waiter"), Confidence::Medium, reasons);
    }
    if major == Some(6) && minor == Some(1) && available("tcp_zerocopy") {
        reasons.push("android14-6.1 compact-waiter family with the tcp path present".to_string());
        return (Some("tcp_zerocopy"), Confidence::Medium, reasons);
    }
    match family {
        Some("STRUCT_OFFSETS_6_6") | Some("STRUCT_OFFSETS_6_12") => {
            reasons.push("family default; the pselect layout was not derived".to_string());
            (Some("select_stack"), Confidence::Low, reasons)
        }
        Some("STRUCT_OFFSETS_6_1") => {
            reasons.push("family default; compact-waiter layout".to_string());
            (Some("tcp_zerocopy"), Confidence::Low, reasons)
        }
        _ => {
            reasons.push(
                "no verified family and no derivable route; review the paths above and pass \
                 --route once confirmed"
                    .to_string(),
            );
            (None, Confidence::Low, reasons)
        }
    }
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

    fn no_routes(_route: &str) -> bool {
        false
    }

    #[test]
    fn pselect_derivation_wins() {
        let (route, confidence, _) = suggest(true, &no_routes, None, Some(5), Some(15));
        assert_eq!(route, Some("select_stack"));
        assert_eq!(confidence, Confidence::High);
    }

    #[test]
    fn major5_multicast_fallback() {
        let available = |route: &str| route == "multicast_waiter";
        let (route, confidence, _) = suggest(false, &available, None, Some(5), Some(15));
        assert_eq!(route, Some("multicast_waiter"));
        assert_eq!(confidence, Confidence::Medium);
    }

    #[test]
    fn android14_61_prefers_tcp_when_pselect_is_not_derived() {
        let available = |route: &str| route == "tcp_zerocopy";
        let (route, confidence, _) = suggest(
            false,
            &available,
            Some("STRUCT_OFFSETS_6_1"),
            Some(6),
            Some(1),
        );
        assert_eq!(route, Some("tcp_zerocopy"));
        assert_eq!(confidence, Confidence::Medium);
    }

    #[test]
    fn family_defaults_are_low_confidence() {
        let (route, confidence, _) = suggest(
            false,
            &no_routes,
            Some("STRUCT_OFFSETS_6_6"),
            Some(6),
            Some(6),
        );
        assert_eq!(route, Some("select_stack"));
        assert_eq!(confidence, Confidence::Low);
        let (route, _, _) = suggest(false, &no_routes, None, Some(5), Some(15));
        assert_eq!(route, None);
    }

    #[test]
    fn unverified_six_x_template_does_not_drive_route_suggestion() {
        let paths = Vec::new();
        let (route, confidence, _) = suggest_route(false, &paths, Some("6.6.92-generic-build"));
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
