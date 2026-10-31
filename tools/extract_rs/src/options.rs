//! The option superset: everything one derivation pass yields for an image.
//!
//! One document per kernel. The app consumes it for the route picker and the
//! page-vs-conditional prompt; the test corpus keeps it as the single golden.
//! A runnable profile is a **cut** of this document: `(superset, route, plan)`,
//! not a separate derivation.
//!
//! Policy (operator, 2026-10-31):
//! - `dump_skip.zeroes`/`__dump_skip.zeroes`, `bm_pmd` and `serial8250_ports`
//!   are unconditioned: they may be applied without asking.
//! - `s3c24xx_serial_ports` is conditioned: its premise (no `samsung,*` node /
//!   driver) is a device fact the app cannot check before W1, so it enters
//!   only an attested plan.
//! - The auto chain is: first unconditioned anchor with a slot -> its in-anchor
//!   scratch -> an unconditioned second region. The attested plan is offered
//!   only when no unconditioned plan is page-free.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::anchor::{self, W1Scratch};
use crate::analysis::RouteVerdict;

pub const SCHEMA_VERSION: u32 = 1;

impl Superset {
    /// Deserialize a stored golden for a cut (the tests and the app).
    pub fn from_value(value: &serde_json::Value) -> Result<Superset, serde_json::Error> {
        serde_json::from_value(value.clone())
    }
}

/// Named anchor/scratch classes, in policy order, with the operator's
/// `conditioned` flag. The scan verdict stays in the entry as evidence.
const NAMED: [(&str, bool); 5] = [
    ("__dump_skip.zeroes", false),
    ("dump_skip.zeroes", false),
    ("bm_pmd", false),
    ("serial8250_ports", false),
    ("s3c24xx_serial_ports", true),
];

#[derive(Debug, Serialize, Deserialize)]
pub struct Superset {
    pub schema_version: u32,
    pub release: String,
    pub kernel_major: Option<u32>,
    pub kernel_phys_load: Option<u64>,
    pub kernel_phys_offset: Option<u64>,
    /// The physical pair's source (`xbl_config FDT`, `uefi memory map`, …),
    /// so the app can show the same advice without a second run.
    pub phys_source: String,
    pub routes: Vec<RouteOption>,
    pub candidates: Vec<CandidateOption>,
    pub plans: Vec<RoutePlans>,
    /// The common profile blocks rendered once (route-less). A cut selects a
    /// route and plan and prepends the route block to these maps.
    pub profile: BTreeMap<String, BTreeMap<String, String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RouteOption {
    pub route: String,
    pub verdict: String,
    pub reason: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub numbers: BTreeMap<String, i64>,
    pub anchor_capable: bool,
    pub geometry: BTreeMap<String, i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorTriple {
    pub image: u64,
    pub bytes: u64,
    pub stride: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScratchPlacement {
    pub image: u64,
    pub window: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reserved_first: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reserved_last: Option<u64>,
}

impl ScratchPlacement {
    fn of(scratch: &W1Scratch) -> Self {
        Self {
            image: scratch.image,
            window: scratch.window,
            reserved_first: scratch.inside_anchor.then_some(scratch.reserved_first),
            reserved_last: scratch.inside_anchor.then_some(scratch.reserved_last),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CandidateOption {
    pub name: String,
    pub image: u64,
    pub extent: u64,
    pub clean_prefix: u64,
    pub verdict: String,
    pub conditioned: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor: Option<AnchorTriple>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub in_anchor_scratch: Option<ScratchPlacement>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub second_region_scratch: Option<ScratchPlacement>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plan {
    pub route: String,
    pub anchor: Option<AnchorTriple>,
    pub scratch: Option<ScratchPlacement>,
    pub page_free: bool,
    pub conditioned: bool,
    /// The anchor candidate's symbol name, for the UI label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor_name: Option<String>,
    /// `in-anchor` or the second-region symbol name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scratch_source: Option<String>,
    pub reason: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RoutePlans {
    pub route: String,
    pub page: Plan,
    /// The safe anchor with a page W1 (no scratch): the lock-source "anchor"
    /// option when no page-free plan is selected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor_only: Option<Plan>,
    /// Every page-free plan, safe first then conditioned. The extractor omits
    /// nothing; the UI decides what to show and when to prompt.
    #[serde(default)]
    pub page_free: Vec<Plan>,
}

/// Parse a rendered profile into `block -> { key: value }`; top-level keys sit
/// under `""`. The superset stores the common blocks this way so a cut can
/// render them without re-deriving anything.
pub fn parse_conf_blocks(text: &str) -> BTreeMap<String, BTreeMap<String, String>> {
    let mut out: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    let mut current: Option<String> = None;
    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if let Some(name) = current.clone() {
            if line == "}" {
                current = None;
                continue;
            }
            if let Some((key, value)) = line.split_once('=') {
                out.entry(name)
                    .or_default()
                    .insert(key.trim().to_string(), value.trim().to_string());
            }
            continue;
        }
        if let Some(rest) = line.strip_suffix('{') {
            current = Some(rest.trim().to_string());
            continue;
        }
        if line == "}" {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            out.entry(String::new())
                .or_default()
                .insert(key.trim().to_string(), value.trim().to_string());
        }
    }
    out
}

pub struct Input<'a> {
    pub release: &'a str,
    pub kernel_major: Option<u32>,
    pub phys_load: Option<u64>,
    pub phys_offset: Option<u64>,
    pub phys_source: &'a str,
    /// Route verdicts, in the extractor's stable order.
    pub verdicts: &'a [RouteVerdict],
    /// Full geometry per feasible route (the cut needs all of them).
    pub geometry: &'a BTreeMap<String, BTreeMap<String, i64>>,
    /// `selinux_state.initialized`; `None` fails the scratch arithmetic closed.
    pub initialized: Option<u32>,
    pub kernel: &'a [u8],
    pub rel_symbols: &'a BTreeMap<String, BTreeSet<u64>>,
    /// Route-less rendered profile text (comments allowed); parsed into
    /// `profile` so the document is self-contained.
    pub common_profile: &'a str,
}

/// Build the superset. Deterministic: candidates in `NAMED` order, routes in
/// verdict order, maps as `BTreeMap`.
pub fn build(input: &Input<'_>) -> Superset {
    let candidates = scan_candidates(&CandidateInput {
        kernel: input.kernel,
        rel_symbols: input.rel_symbols,
        phys_load: input.phys_load,
        phys_offset: input.phys_offset,
        initialized: input.initialized,
    });
    let mut plans = Vec::new();
    for verdict in input.verdicts {
        if verdict.verdict != crate::analysis::Feasibility::Feasible {
            continue;
        }
        plans.push(plans_for(verdict.route, &candidates));
    }
    let routes = input
        .verdicts
        .iter()
        .map(|verdict| RouteOption {
            route: verdict.route.to_string(),
            verdict: verdict.verdict.label().to_string(),
            reason: verdict.reason.clone(),
            numbers: verdict.numbers.clone(),
            anchor_capable: verdict.route != "tcp_zerocopy",
            geometry: input
                .geometry
                .get(verdict.route)
                .cloned()
                .unwrap_or_default(),
        })
        .collect();
    Superset {
        schema_version: SCHEMA_VERSION,
        profile: parse_conf_blocks(input.common_profile),
        release: input.release.to_string(),
        kernel_major: input.kernel_major,
        kernel_phys_load: input.phys_load,
        kernel_phys_offset: input.phys_offset,
        phys_source: input.phys_source.to_string(),
        routes,
        candidates,
        plans,
    }
}

/// The inputs the candidate scan needs. Shared by the superset builder and
/// the CLI's `--format conf --anchor`, which follows the same auto plan.
pub struct CandidateInput<'a> {
    pub kernel: &'a [u8],
    pub rel_symbols: &'a BTreeMap<String, BTreeSet<u64>>,
    pub phys_load: Option<u64>,
    pub phys_offset: Option<u64>,
    pub initialized: Option<u32>,
}

pub fn scan_candidates(input: &CandidateInput<'_>) -> Vec<CandidateOption> {
    let bounds = anchor::bounds_from(input.rel_symbols);
    let refs = anchor::scan_references(input.kernel, &bounds);
    let mut out = Vec::new();
    for (name, conditioned) in NAMED {
        let Some(candidate) = anchor::named_candidate(input.rel_symbols, &bounds, name) else {
            continue;
        };
        let assessment = anchor::assess(&candidate, &refs, input.rel_symbols, &bounds);
        let triple = anchor::profile_triple(&assessment);
        let delta = input.phys_load.and_then(|load| {
            let offset = input.phys_offset.unwrap_or(0x8000_0000);
            let delta = load.checked_sub(offset)?;
            (delta & 0xffff == 0).then_some(delta)
        });
        let in_anchor_scratch = delta.and_then(|delta| {
            let initialized = input.initialized?;
            let (image, bytes, stride) = triple?;
            anchor::pick_w1_scratch(image, bytes, stride, delta, initialized)
                .map(|scratch| ScratchPlacement::of(&scratch))
        });
        let second_region_scratch = delta.and_then(|delta| {
            let initialized = input.initialized?;
            anchor::pick_w1_scratch_in_symbol(
                candidate.offset,
                candidate.extent,
                input.kernel,
                delta,
                initialized,
            )
            .map(|scratch| ScratchPlacement::of(&scratch))
        });
        out.push(CandidateOption {
            name: candidate.name,
            image: candidate.offset,
            extent: candidate.extent,
            clean_prefix: anchor::clean_prefix(&assessment, family_stride()),
            verdict: assessment.verdict.label().to_string(),
            conditioned,
            anchor: triple.map(|(image, bytes, stride)| AnchorTriple {
                image,
                bytes,
                stride,
            }),
            in_anchor_scratch,
            second_region_scratch,
        });
    }
    out
}

fn family_stride() -> u64 {
    crate::family::ANCHOR_STRIDE
}

/// The default plan for a route: the first safe (unconditioned) page-free
/// option, else the safe anchor with a page W1, else page. The CLI renders
/// this; the app applies the user-facing rules over the full list.
pub fn auto_plan(route: &str, candidates: &[CandidateOption]) -> Plan {
    let plans = plans_for(route, candidates);
    plans
        .page_free
        .iter()
        .find(|plan| !plan.conditioned)
        .cloned()
        .or_else(|| plans.anchor_only.clone())
        .unwrap_or(plans.page)
}

fn plans_for(route: &str, candidates: &[CandidateOption]) -> RoutePlans {
    let page = Plan {
        route: route.to_string(),
        anchor: None,
        scratch: None,
        page_free: false,
        conditioned: false,
        anchor_name: None,
        scratch_source: None,
        reason: "page".to_string(),
    };
    if route == "tcp_zerocopy" {
        return RoutePlans {
            route: route.to_string(),
            page,
            anchor_only: None,
            page_free: Vec::new(),
        };
    }
    let mut page_free = Vec::new();
    for anchor in candidates
        .iter()
        .filter(|candidate| candidate.anchor.is_some())
    {
        if let Some(scratch) = &anchor.in_anchor_scratch {
            page_free.push(page_free_plan(
                route,
                anchor,
                scratch,
                anchor.conditioned,
                "in-anchor",
            ));
        } else {
            for region in candidates
                .iter()
                .filter(|region| region.name != anchor.name)
            {
                if let Some(scratch) = &region.second_region_scratch {
                    page_free.push(page_free_plan(
                        route,
                        anchor,
                        scratch,
                        anchor.conditioned || region.conditioned,
                        &region.name,
                    ));
                }
            }
        }
    }
    /* Stable sort: safe plans first, NAMED order preserved inside each group. */
    page_free.sort_by_key(|plan| plan.conditioned);
    let anchor_only = candidates
        .iter()
        .find(|candidate| !candidate.conditioned && candidate.anchor.is_some())
        .map(|candidate| Plan {
            route: route.to_string(),
            anchor: candidate.anchor.clone(),
            scratch: None,
            page_free: false,
            conditioned: false,
            anchor_name: Some(candidate.name.clone()),
            scratch_source: None,
            reason: "anchor lock, page W1".to_string(),
        });
    RoutePlans {
        route: route.to_string(),
        page,
        anchor_only,
        page_free,
    }
}

fn page_free_plan(
    route: &str,
    anchor: &CandidateOption,
    scratch: &ScratchPlacement,
    conditioned: bool,
    source: &str,
) -> Plan {
    Plan {
        route: route.to_string(),
        anchor: anchor.anchor.clone(),
        scratch: Some(scratch.clone()),
        page_free: true,
        conditioned,
        anchor_name: Some(anchor.name.clone()),
        scratch_source: Some(source.to_string()),
        reason: if conditioned {
            "conditional page-free plan".to_string()
        } else {
            "unconditional page-free plan".to_string()
        },
    }
}

/// Which plan of a route a cut materializes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanKind {
    Page,
    Auto,
    Attested,
}

impl PlanKind {
    pub fn label(self) -> &'static str {
        match self {
            PlanKind::Page => "page",
            PlanKind::Auto => "auto",
            PlanKind::Attested => "attested",
        }
    }
}

/// Materialize a runnable profile from the superset: `(superset, route, plan)`.
/// No derivation happens here; the common blocks were rendered once and the
/// route/plan select which of the already-derived options is written.
pub fn cut(superset: &Superset, route: &str, kind: PlanKind) -> Option<String> {
    let route_option = superset
        .routes
        .iter()
        .find(|option| option.route == route && option.verdict == "feasible")?;
    let plans = superset.plans.iter().find(|plans| plans.route == route)?;
    let plan = match kind {
        PlanKind::Page => &plans.page,
        /* Auto = the first safe page-free option; without one, the safe
         * anchor with a page W1 (the CLI renders this); else page. */
        PlanKind::Auto => plans
            .page_free
            .iter()
            .find(|plan| !plan.conditioned)
            .or(plans.anchor_only.as_ref())
            .unwrap_or(&plans.page),
        PlanKind::Attested => plans.page_free.iter().find(|plan| plan.conditioned)?,
    };
    Some(render_cut(superset, route, route_option, plan, kind.label()))
}

/// Materialize one explicitly selected option (the app's picker). The plan is
/// taken from the superset's `page_free` list (or `anchor_only`/`page`).
pub fn cut_plan(superset: &Superset, route: &str, plan: &Plan) -> Option<String> {
    let route_option = superset
        .routes
        .iter()
        .find(|option| option.route == route && option.verdict == "feasible")?;
    let label = plan
        .anchor_name
        .as_deref()
        .map(|name| {
            format!(
                "{name}/{}",
                plan.scratch_source.as_deref().unwrap_or("page")
            )
        })
        .unwrap_or_else(|| "page".to_string());
    Some(render_cut(superset, route, route_option, plan, &label))
}

fn render_cut(
    superset: &Superset,
    route: &str,
    route_option: &RouteOption,
    plan: &Plan,
    label: &str,
) -> String {
    let top = superset.profile.get("").cloned().unwrap_or_default();
    let value = |key: &str| top.get(key).cloned();
    let mut lines = vec![
        format!(
            "# GhostLock kernel profile: {} (HOCON, self-contained).",
            superset.release
        ),
        format!("# cut from the option superset: route={route} plan={label}"),
    ];
    for key in [
        "release",
        "schema_version",
        "kernel_major",
        "recommend_shizuku",
        "kernel_phys_load",
        "kernel_phys_offset",
    ] {
        if let Some(value) = value(key) {
            lines.push(format!("{key} = {value}"));
        }
    }
    lines.push("route {".to_string());
    lines.push(format!("  {route} {{"));
    let mut geometry: BTreeMap<&str, &i64> = route_option
        .geometry
        .iter()
        .map(|(key, value)| (key.as_str(), value))
        .collect();
    if let Some(anchor) = &plan.anchor {
        for key in ["waiter_shift", "compact_waiter"] {
            if let Some(value) = geometry.remove(key) {
                lines.push(format!("    {key} = {value}"));
            }
        }
        for (key, value) in &geometry {
            lines.push(format!("    {key} = {value}"));
        }
        lines.push(format!("    lock_anchor_image = {}", anchor.image));
        lines.push(format!("    lock_anchor_bytes = {}", anchor.bytes));
        lines.push(format!("    lock_anchor_stride = {}", anchor.stride));
    } else {
        for (key, value) in &geometry {
            lines.push(format!("    {key} = {value}"));
        }
    }
    lines.push("  }".to_string());
    lines.push("}".to_string());
    if let Some(fallback) = superset.profile.get("fallback") {
        lines.push("fallback {".to_string());
        for (key, value) in fallback {
            lines.push(format!("  {key} = {value}"));
        }
        lines.push("}".to_string());
    }
    if let Some(selinux) = superset.profile.get("selinux") {
        lines.push("selinux {".to_string());
        for (key, value) in selinux {
            lines.push(format!("  {key} = {value}"));
        }
        lines.push("}".to_string());
    }
    if let Some(scratch) = &plan.scratch {
        lines.push("w1_scratch {".to_string());
        lines.push(format!("  image = {}", scratch.image));
        lines.push("}".to_string());
    }
    for block in ["kernelsnitch", "task_struct", "cred", "offset", "waiter_layout"] {
        if let Some(entries) = superset.profile.get(block) {
            lines.push(format!("{block} {{"));
            for (key, value) in entries {
                lines.push(format!("  {key} = {value}"));
            }
            lines.push("}".to_string());
        }
    }
    lines.join("\n") + "\n"
}

#[cfg(test)]
mod tests {
    use super::*;

    fn placement(image: u64, inside: bool) -> ScratchPlacement {
        ScratchPlacement {
            image,
            window: 0x100,
            reserved_first: inside.then_some(8),
            reserved_last: inside.then_some(8),
        }
    }

    fn candidate(
        name: &str,
        conditioned: bool,
        in_anchor: bool,
        second: bool,
    ) -> CandidateOption {
        CandidateOption {
            name: name.to_string(),
            image: 0x1000,
            extent: 0x1000,
            clean_prefix: 0x1000,
            verdict: "needs-review".to_string(),
            conditioned,
            anchor: Some(AnchorTriple {
                image: 0x1000,
                bytes: 0x1000,
                stride: 32,
            }),
            in_anchor_scratch: in_anchor.then(|| placement(0x1000, true)),
            second_region_scratch: second.then(|| placement(0x2000, false)),
        }
    }

    #[test]
    fn all_safe_page_free_options_are_listed_and_auto_takes_the_first() {
        let candidates = vec![
            candidate("dump_skip.zeroes", false, true, false),
            candidate("bm_pmd", false, false, true),
            candidate("serial8250_ports", false, true, false),
        ];
        let plans = plans_for("select_stack", &candidates);
        let safe: Vec<_> = plans.page_free.iter().filter(|plan| !plan.conditioned).collect();
        /* dump_skip and serial8250 have in-anchor slots; bm_pmd has no scratch
         * that another safe region can host in this synthetic set. */
        assert_eq!(safe.len(), 2, "every safe anchor space is offered");
        assert_eq!(safe[0].anchor_name.as_deref(), Some("dump_skip.zeroes"));
        assert_eq!(safe[0].scratch_source.as_deref(), Some("in-anchor"));
        let auto = auto_plan("select_stack", &candidates);
        assert!(auto.page_free);
        assert_eq!(auto.anchor_name.as_deref(), Some("dump_skip.zeroes"));
        assert_eq!(auto.scratch.as_ref().unwrap().image, 0x1000);
    }

    #[test]
    fn an_anchor_without_an_in_anchor_slot_gets_second_region_options() {
        let mut dump = candidate("dump_skip.zeroes", false, false, false);
        dump.second_region_scratch = None;
        let candidates = vec![
            dump,
            candidate("bm_pmd", false, false, true),
            candidate("serial8250_ports", false, false, true),
        ];
        let plans = plans_for("select_stack", &candidates);
        let safe: Vec<_> = plans.page_free.iter().filter(|plan| !plan.conditioned).collect();
        /* Every anchor without an in-anchor slot gets every *other* safe
         * second region: dump x {bm_pmd, serial}, bm_pmd x serial, serial x
         * bm_pmd. The UI filters/groups; the extractor omits nothing. */
        assert_eq!(safe.len(), 4);
        assert_eq!(safe[0].anchor_name.as_deref(), Some("dump_skip.zeroes"));
        assert_eq!(safe[0].scratch_source.as_deref(), Some("bm_pmd"));
        assert_eq!(safe[1].anchor_name.as_deref(), Some("dump_skip.zeroes"));
        assert_eq!(safe[1].scratch_source.as_deref(), Some("serial8250_ports"));
        let auto = auto_plan("select_stack", &candidates);
        assert!(auto.page_free);
        assert_eq!(auto.scratch_source.as_deref(), Some("bm_pmd"));
    }

    #[test]
    fn a_conditional_second_region_is_listed_but_not_auto() {
        let candidates = vec![
            candidate("dump_skip.zeroes", false, false, false),
            candidate("bm_pmd", false, false, false),
            candidate("serial8250_ports", false, false, false),
            candidate("s3c24xx_serial_ports", true, false, true),
        ];
        let plans = plans_for("sigreturn", &candidates);
        assert!(
            plans.page_free.iter().all(|plan| plan.conditioned),
            "only conditioned plans exist"
        );
        assert!(!plans.page_free.is_empty());
        let auto = auto_plan("sigreturn", &candidates);
        assert!(!auto.page_free);
        assert!(auto.anchor.is_some(), "auto falls back to the safe anchor");
    }

    #[test]
    fn a_conditional_anchor_option_is_listed() {
        let mut conditioned = candidate("s3c24xx_serial_ports", true, true, false);
        conditioned.anchor = Some(AnchorTriple {
            image: 0x3000,
            bytes: 0x1000,
            stride: 32,
        });
        let candidates = vec![
            candidate("dump_skip.zeroes", false, false, false),
            conditioned,
        ];
        let plans = plans_for("select_stack", &candidates);
        let conditioned_plans: Vec<_> = plans
            .page_free
            .iter()
            .filter(|plan| plan.conditioned)
            .collect();
        assert_eq!(conditioned_plans.len(), 1);
        assert_eq!(
            conditioned_plans[0].anchor.as_ref().unwrap().image,
            0x3000
        );
        assert!(!auto_plan("select_stack", &candidates).page_free);
    }

    #[test]
    fn tcp_has_no_page_free_options() {
        let candidates = vec![candidate("dump_skip.zeroes", false, true, false)];
        let plans = plans_for("tcp_zerocopy", &candidates);
        assert!(plans.page_free.is_empty());
        assert!(plans.anchor_only.is_none());
        assert!(!auto_plan("tcp_zerocopy", &candidates).page_free);
    }

    fn sample_superset() -> Superset {
        let mut profile = BTreeMap::new();
        profile.insert(
            String::new(),
            BTreeMap::from([
                ("release".to_string(), "\"r\"".to_string()),
                ("schema_version".to_string(), "1".to_string()),
                ("kernel_major".to_string(), "6".to_string()),
                ("kernel_phys_load".to_string(), "123".to_string()),
                ("kernel_phys_offset".to_string(), "null".to_string()),
            ]),
        );
        profile.insert(
            "selinux".to_string(),
            BTreeMap::from([
                ("enforcing".to_string(), "0".to_string()),
                ("initialized".to_string(), "1".to_string()),
            ]),
        );
        profile.insert(
            "task_struct".to_string(),
            BTreeMap::from([("prio".to_string(), "132".to_string())]),
        );
        let anchor = AnchorTriple {
            image: 0x1000,
            bytes: 0x1000,
            stride: 32,
        };
        let scratch = placement(0x1000, true);
        let page = Plan {
            route: "select_stack".to_string(),
            anchor: None,
            scratch: None,
            page_free: false,
            conditioned: false,
            anchor_name: None,
            scratch_source: None,
            reason: "page".to_string(),
        };
        let page_free = Plan {
            route: "select_stack".to_string(),
            anchor: Some(anchor),
            scratch: Some(scratch),
            page_free: true,
            conditioned: false,
            anchor_name: Some("dump_skip.zeroes".to_string()),
            scratch_source: Some("in-anchor".to_string()),
            reason: String::new(),
        };
        Superset {
            schema_version: SCHEMA_VERSION,
            release: "r".to_string(),
            kernel_major: Some(6),
            kernel_phys_load: Some(123),
            kernel_phys_offset: None,
            phys_source: "unset".to_string(),
            routes: vec![RouteOption {
                route: "select_stack".to_string(),
                verdict: "feasible".to_string(),
                reason: String::new(),
                numbers: BTreeMap::new(),
                anchor_capable: true,
                geometry: BTreeMap::from([
                    ("waiter_shift".to_string(), -2),
                    ("compact_waiter".to_string(), 1),
                ]),
            }],
            candidates: Vec::new(),
            plans: vec![RoutePlans {
                route: "select_stack".to_string(),
                page,
                anchor_only: None,
                page_free: vec![page_free],
            }],
            profile,
        }
    }

    #[test]
    fn cut_writes_the_selected_plan() {
        let superset = sample_superset();
        let auto = cut(&superset, "select_stack", PlanKind::Auto).expect("auto cut");
        assert!(auto.contains("lock_anchor_image = 4096"));
        assert!(auto.contains("w1_scratch {"));
        assert!(auto.contains("selinux {"));
        assert!(auto.contains("prio = 132"));
        let page = cut(&superset, "select_stack", PlanKind::Page).expect("page cut");
        assert!(!page.contains("lock_anchor_image"));
        assert!(!page.contains("w1_scratch"));
        assert!(cut(&superset, "select_stack", PlanKind::Attested).is_none());
        assert!(cut(&superset, "sigreturn", PlanKind::Auto).is_none());
        let explicit = cut_plan(&superset, "select_stack", &superset.plans[0].page_free[0])
            .expect("explicit cut");
        assert!(explicit.contains("lock_anchor_image = 4096"));
    }
}
