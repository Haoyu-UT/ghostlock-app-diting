// Throwaway diagnostic (local-only, do NOT commit).
//
// Purpose: run the select_stack (pselect) geometry derivation on the diting
// boot.img *without BTF* by replicating derive_pselect_layout()'s logic with
// the BTF-sourced inputs substituted from the CPH2521 reference
// (rt_mutex_waiter.pi_tree_entry = 0x18 as used by the tool's own constant,
// wake_state probed empirically below), and dump the raw layout evidence:
//   A) pselect/futex chain validation + frame sums (the tool's arithmetic)
//   B) waiter-field stores in futex_wait_requeue_pi (real struct offsets)
//   C) the core_sys_select fd_set buffer candidates + threshold evidence
//
// The tool's own pipeline: shift = (buffer_depth - waiter_depth) / 8  (u64,
// qwords the waiter starts above the fd_set buffer), and the emitted profile
// value is `shift as i64 - 2` (main.rs: "derived {} - 2").

use ghostlock_extract::derive::{OBJDUMP_CAP, PSELECT_ROUTE_NFDS, RelSymbols};
use ghostlock_extract::disasm::{
    add_sp_immediates, cmp_immediates, disassemble_range, first_sp_frame, has_direct_call,
    validate_frame_live_at,
};
use regex::Regex;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;

const IMG: &str = "/tmp/diting.img";
const KALLSYMS: &str =
    "/home/haoyu/projects/redmi_ultra_k50_root/external/port/device-dump/run8/ghostlock-dumps/10-kallsyms.txt";

fn load_symbols() -> (RelSymbols, Vec<u64>, u64) {
    let km = fs::read_to_string(KALLSYMS).unwrap();
    let mut addrs: BTreeMap<String, BTreeSet<u64>> = BTreeMap::new();
    for line in km.lines() {
        let mut it = line.split_whitespace();
        if let (Some(a), Some(_t), Some(n)) = (it.next(), it.next(), it.next()) {
            if let Ok(v) = u64::from_str_radix(a, 16) {
                if v != 0 {
                    addrs.entry(n.to_string()).or_default().insert(v);
                }
            }
        }
    }
    let text = *addrs["_text"].iter().next().unwrap();
    let mut rel: RelSymbols = BTreeMap::new();
    let mut sorted: Vec<u64> = Vec::new();
    for (name, set) in &addrs {
        let mut relset = BTreeSet::new();
        for a in set {
            if *a >= text {
                relset.insert(a - text);
            }
        }
        if !relset.is_empty() {
            for off in &relset {
                if *off < 0x4000000 {
                    sorted.push(*off);
                }
            }
            rel.insert(name.clone(), relset);
        }
    }
    sorted.sort_unstable();
    sorted.dedup();
    (rel, sorted, text)
}

fn sym(symbols: &RelSymbols, name: &str) -> Option<u64> {
    symbols.get(name).and_then(|s| s.iter().next()).copied()
}

fn dis(
    img: &[u8],
    symbols: &RelSymbols,
    sorted: &[u64],
    name: &str,
) -> Option<Vec<String>> {
    let start = sym(symbols, name)? as usize;
    let higher = sorted.iter().find(|off| **off as usize > start);
    let stop = (start + OBJDUMP_CAP).min(higher.map_or(start + OBJDUMP_CAP, |o| *o as usize));
    Some(disassemble_range(img, start, stop).unwrap())
}

fn main() {
    let img = fs::read(IMG).unwrap();
    let (symbols, sorted, text) = load_symbols();
    println!("_text = 0x{text:x}; image len 0x{:x}", img.len());

    // ---- chain symbols ----
    let mut names: Vec<(&str, &str)> = vec![
        ("pselect_wrapper", "__arm64_sys_pselect6"),
        ("pselect_core", "core_sys_select"),
        ("futex_wrapper", "__arm64_sys_futex"),
        ("futex_dispatch", "do_futex"),
        ("futex_wait", "futex_wait_requeue_pi"),
    ];
    let has_dispatch = sym(&symbols, "do_pselect").is_some();
    if has_dispatch {
        names.push(("pselect_dispatch", "do_pselect"));
    }
    println!("do_pselect present: {has_dispatch}");

    let mut dis_by_key: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for (key, name) in &names {
        match dis(&img, &symbols, &sorted, name) {
            Some(lines) => {
                println!("symbol {name}: off=0x{:x} lines={}", sym(&symbols, name).unwrap(), lines.len());
                dis_by_key.insert(key, lines);
            }
            None => {
                println!("symbol {name}: MISSING");
            }
        }
    }

    // ---- pselect chain ----
    let core_off = sym(&symbols, "core_sys_select").unwrap();
    let mut pselect_chain = vec!["pselect_wrapper"];
    if has_direct_call(&dis_by_key["pselect_wrapper"], core_off) {
        println!("pselect: wrapper calls core_sys_select DIRECTLY (inline path)");
    } else if has_dispatch && has_direct_call(&dis_by_key["pselect_wrapper"], sym(&symbols, "do_pselect").unwrap()) {
        println!("pselect: wrapper -> do_pselect -> core_sys_select");
        pselect_chain.push("pselect_dispatch");
    } else {
        println!("pselect: FAIL wrapper calls neither core_sys_select nor do_pselect");
        return;
    }
    pselect_chain.push("pselect_core");

    // ---- futex chain ----
    let wait_off = sym(&symbols, "futex_wait_requeue_pi").unwrap();
    let mut futex_chain = vec!["futex_wrapper"];
    if has_direct_call(&dis_by_key["futex_wrapper"], wait_off) {
        println!("futex: wrapper calls futex_wait_requeue_pi DIRECTLY");
    } else if has_direct_call(&dis_by_key["futex_wrapper"], sym(&symbols, "do_futex").unwrap()) {
        println!("futex: wrapper -> do_futex -> futex_wait_requeue_pi");
        futex_chain.push("futex_dispatch");
    } else {
        println!("futex: FAIL wrapper calls neither");
        return;
    }
    futex_chain.push("futex_wait");

    // frame-live validation on the call edges (same as the tool)
    for (chain, tag) in [(&pselect_chain, "pselect"), (&futex_chain, "futex")] {
        for pair in chain.windows(2) {
            let caller = pair[0];
            let callee_full = names.iter().find(|(k, _)| *k == pair[1]).unwrap().1;
            let target = sym(&symbols, callee_full).unwrap();
            let anchor = Regex::new(&format!(r"(?i)\bbl\s+0x{target:x}\b")).unwrap();
            let caller_full = names.iter().find(|(k, _)| *k == caller).unwrap().1;
            match validate_frame_live_at(&dis_by_key[caller], &anchor, caller_full) {
                Ok(()) => println!("  [{tag}] frame live at bl->{callee_full}: OK"),
                Err(e) => println!("  [{tag}] frame live at bl->{callee_full}: FAIL {e}"),
            }
        }
    }

    // ---- frame sums ----
    let mut frames: BTreeMap<String, u64> = BTreeMap::new();
    for (key, name) in &names {
        if let Some(lines) = dis_by_key.get(key) {
            match first_sp_frame(lines, name) {
                Ok(f) => {
                    println!("frame {name} = 0x{f:x}");
                    frames.insert((*key).to_string(), f);
                }
                Err(e) => println!("frame {name}: FAIL {e}"),
            }
        }
    }
    let pselect_sum: u64 = pselect_chain.iter().map(|k| frames[*k]).sum();
    let futex_sum: u64 = futex_chain.iter().map(|k| frames[*k]).sum();
    println!("pselect chain {} sum=0x{pselect_sum:x}", pselect_chain.join("->"));
    println!("futex   chain {} sum=0x{futex_sum:x}", futex_chain.join("->"));

    // ---- waiter local (pi_tree_entry = 0x18, the tool's constant) ----
    let fw = &dis_by_key["futex_wait"];
    let mut candidates: Vec<(String, u64)> = Vec::new();
    for (reg, imm) in add_sp_immediates(fw) {
        let re = Regex::new(&format!(r"(?i)\badd\s+x\d+,\s*{reg},\s*#0x18\b")).unwrap();
        if fw.iter().any(|l| re.is_match(l)) {
            candidates.push((reg, imm));
        }
    }
    let mut seen = BTreeSet::new();
    candidates.retain(|(_, imm)| seen.insert(*imm));
    println!("waiter candidates (add xN,sp,#imm + add xM,xN,#0x18): {candidates:?}");
    let (waiter_reg, waiter_local) = candidates[0].clone();
    let anchor = Regex::new(&format!(r"(?i)\badd\s+{waiter_reg},\s*sp,\s*#0x{waiter_local:x}\b")).unwrap();
    match validate_frame_live_at(fw, &anchor, "futex_wait") {
        Ok(()) => println!("waiter anchor {waiter_reg},sp,#0x{waiter_local:x}: unique + frame live OK"),
        Err(e) => println!("waiter anchor FAIL: {e}"),
    }
    // cross-validation stores at [sp, #waiter_local] and +wake_state candidates
    for extra in [0u64, 0x18, 0x40, 0x50, 0x60] {
        let re = Regex::new(&format!(r"(?i)\[sp,\s*#0x{:x}\]", waiter_local + extra)).unwrap();
        let hits: Vec<&String> = fw.iter().filter(|l| re.is_match(l)).collect();
        println!(
            "  store [sp,#0x{:x}] (=0x{waiter_local:x}+0x{extra:x}): {} hits {:?}",
            waiter_local + extra,
            hits.len(),
            hits.iter().take(3).collect::<Vec<_>>()
        );
    }

    // ---- buffer in core_sys_select ----
    let core = &dis_by_key["pselect_core"];
    let add_sp = add_sp_immediates(core);
    let mut buffer_candidates: BTreeSet<u64> = BTreeSet::new();
    for (reg, imm) in &add_sp {
        let peers: Vec<&String> = add_sp
            .iter()
            .filter(|(peer, peer_imm)| peer_imm == imm && peer != reg)
            .map(|(peer, _)| peer)
            .collect();
        for peer in peers {
            let re = Regex::new(&format!(r"(?i)\bcmp\s+{reg},\s*{peer}\b")).unwrap();
            let re2 = Regex::new(&format!(r"(?i)\bcmp\s+{peer},\s*{reg}\b")).unwrap();
            let hit = core.iter().find(|l| re.is_match(l) || re2.is_match(l));
            if let Some(line) = hit {
                println!("  buffer candidate imm=0x{imm:x} via {reg}/{peer}: {line}");
                buffer_candidates.insert(*imm);
            }
        }
    }
    println!("buffer candidates: {:?}", buffer_candidates.iter().map(|v| format!("{v:#x}")).collect::<Vec<_>>());
    let mut imm_counts: BTreeMap<u64, usize> = BTreeMap::new();
    for (_, imm) in &add_sp {
        *imm_counts.entry(*imm).or_default() += 1;
    }
    println!("all add-sp immediates in core_sys_select (imm: count):");
    for (imm, count) in &imm_counts {
        println!("  0x{imm:x}: {count}");
    }
    println!("cmp immediates in core_sys_select: {:?}", cmp_immediates(core).iter().map(|v| format!("0x{v:x}")).collect::<Vec<_>>());

    // ---- threshold (fds_bytes=40 must satisfy 40 < t <= 48) ----
    let fds_bytes = ((PSELECT_ROUTE_NFDS + 63) / 64) * 8;
    let ok = cmp_immediates(core).iter().any(|t| fds_bytes < *t && *t <= fds_bytes + 8);
    println!("fds_bytes={fds_bytes}; stack-path threshold present: {ok}");

    // ---- math ----
    let buffer = *buffer_candidates.iter().next().unwrap();
    let pselect_word0 = -(pselect_sum as i64) + buffer as i64;
    let futex_waiter = -(futex_sum as i64) + waiter_local as i64;
    let delta = futex_waiter - pselect_word0;
    println!("pselect_word0 = {pselect_word0} (buffer depth = 0x{:x})", pselect_sum - buffer);
    println!("futex_waiter = {futex_waiter} (waiter depth = 0x{:x})", futex_sum - waiter_local);
    println!("delta = {delta}");
    if delta < 0 || delta % 8 != 0 {
        println!("=> NOT a non-negative qword: derivation would FAIL here");
    } else {
        let shift = (delta / 8) as i64;
        println!("=> derived shift = {shift} qwords; profile value (derived - 2) = {}", shift - 2);
        println!("   app 6.6 table (lock word 13): feasible iff derived <= 3  => {}", if shift <= 3 { "IN BAND" } else { "OUT" });
        println!("   app compact table (lock word 9): feasible iff derived <= 7 => {}", if shift <= 7 { "IN BAND" } else { "OUT" });
        println!("   struct-relative 5.10 (lock word 7): feasible iff derived <= 9 => {}", if shift <= 9 { "IN BAND" } else { "OUT" });
    }

    // ================= layout probes =================
    println!("\n==== futex_wait_requeue_pi: x27-relative accesses ====");
    let x27_imm = Regex::new(r"(?i)\[(x\d+),\s*#0x([0-9a-f]+)\]").unwrap();
    let mut x27_offsets: BTreeSet<u64> = BTreeSet::new();
    let mut x27_lines: Vec<String> = Vec::new();
    for line in fw.iter() {
        if !line.contains("x27") {
            continue;
        }
        x27_lines.push(line.clone());
        for caps in x27_imm.captures_iter(line) {
            if caps[1].eq_ignore_ascii_case("x27") {
                x27_offsets.insert(u64::from_str_radix(&caps[2], 16).unwrap());
            }
        }
    }
    println!("offsets seen via [x27,#imm]: {:?}", x27_offsets.iter().map(|v| format!("0x{v:x}")).collect::<Vec<_>>());
    println!("-- first 70 x27 lines --");
    for line in x27_lines.iter().take(70) {
        println!("  {line}");
    }

    println!("\n==== futex_wait_requeue_pi: RB_CLEAR_NODE self-store candidates ====");
    for (i, line) in fw.iter().enumerate() {
        if let Some(caps) = Regex::new(r"(?i)\badd\s+(x\d+),\s*x27,\s*#0x([0-9a-f]+)").unwrap().captures(line) {
            let reg = &caps[1];
            let imm = &caps[2];
            for j in i + 1..(i + 3).min(fw.len()) {
                let selfstore = Regex::new(&format!(r"(?i)\bstr\s+{reg},\s*\[{reg}\]")).unwrap();
                if selfstore.is_match(&fw[j]) {
                    println!("  self-store at +0x{imm}: {line} | {}", fw[j]);
                }
            }
        }
    }
    println!("\n==== futex_wait_requeue_pi: str xzr stores ====");
    for line in fw.iter() {
        if Regex::new(r"(?i)\bst(r?p)?\s+xzr").unwrap().is_match(line) && line.contains("sp") {
            println!("  {line}");
        }
    }
    println!("\n-- futex_wait_requeue_pi first 45 lines --");
    for line in fw.iter().take(45) {
        println!("  {line}");
    }

    println!("\n==== core_sys_select first 60 lines ====");
    for line in core.iter().take(60) {
        println!("  {line}");
    }
    let _ = fs::write("/tmp/disasm-pselect-core.txt", core.join("\n"));
    let _ = fs::write("/tmp/disasm-pselect-futex.txt", fw.join("\n"));
    println!("dumps: /tmp/disasm-pselect-core.txt /tmp/disasm-pselect-futex.txt");
}
