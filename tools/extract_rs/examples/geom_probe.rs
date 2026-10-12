// Throwaway diagnostic (local-only, do NOT commit).
//
// Purpose: run the select_stack (pselect) geometry derivation on ANY diting
// kernel image (boot.img or raw Image), using the image's own recovered
// kallsyms instead of a dumped /proc/kallsyms. Replicates
// derive_pselect_layout()'s BTF-free arithmetic:
//   shift = (buffer_depth - waiter_depth) / 8   (qwords the waiter starts
//           above the fd_set buffer)
//   profile value = shift - 2
//
// usage: cargo run --release --example geom_probe -- <image>

use ghostlock_extract::boot::BootImage;
use ghostlock_extract::derive::{OBJDUMP_CAP, PSELECT_ROUTE_NFDS, RelSymbols};
use ghostlock_extract::disasm::{
    add_sp_immediates, cmp_immediates, disassemble_range, first_sp_frame, has_direct_call,
    validate_frame_live_at,
};
use ghostlock_extract::kallsyms;
use ghostlock_extract::kallsyms_finder;
use regex::Regex;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

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
    disassemble_range(img, start, stop).ok()
}

fn main() {
    let path = std::env::args().nth(1).expect("usage: geom_probe <image>");
    let boot = BootImage::load(Path::new(&path)).expect("load image");
    println!("image: {path}");
    println!("release: {:?}", boot.release());
    let btf_at = boot.embedded_btf_at();
    let btf_pair = btf_at.as_ref().map(|(offset, blob)| (*offset, blob.len()));
    let ks = kallsyms_finder::recover(&boot.kernel, btf_pair).expect("kallsyms recovery");
    let base = kallsyms::unique(&ks.symbols, "_text")
        .or_else(|| kallsyms::unique(&ks.symbols, "_head"))
        .expect("_text/_head");
    let (rel, sorted) = ghostlock_extract::derive::relative_symbols(&ks.symbols, base);
    println!("kallsyms: {} symbols; _text=0x{base:x}", ks.symbols.len());

    let img = &boot.kernel;

    // ---- chain symbols ----
    let mut names: Vec<(&str, &str)> = vec![
        ("pselect_wrapper", "__arm64_sys_pselect6"),
        ("pselect_core", "core_sys_select"),
        ("futex_wrapper", "__arm64_sys_futex"),
        ("futex_dispatch", "do_futex"),
        ("futex_wait", "futex_wait_requeue_pi"),
    ];
    let has_dispatch = sym(&rel, "do_pselect").is_some();
    if has_dispatch {
        names.push(("pselect_dispatch", "do_pselect"));
    }

    let mut dis_by_key: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for (key, name) in &names {
        match dis(img, &rel, &sorted, name) {
            Some(lines) => {
                println!("symbol {name}: off=0x{:x} lines={}", sym(&rel, name).unwrap(), lines.len());
                dis_by_key.insert(key, lines);
            }
            None => println!("symbol {name}: MISSING"),
        }
    }

    // ---- pselect chain ----
    let core_off = match sym(&rel, "core_sys_select") {
        Some(v) => v,
        None => {
            println!("core_sys_select MISSING -> cannot derive");
            return;
        }
    };
    let mut pselect_chain = vec!["pselect_wrapper"];
    if has_direct_call(&dis_by_key["pselect_wrapper"], core_off) {
        println!("pselect: wrapper calls core_sys_select DIRECTLY (inline path)");
    } else if has_dispatch
        && has_direct_call(&dis_by_key["pselect_wrapper"], sym(&rel, "do_pselect").unwrap())
    {
        println!("pselect: wrapper -> do_pselect -> core_sys_select");
        pselect_chain.push("pselect_dispatch");
    } else {
        println!("pselect: FAIL wrapper calls neither core_sys_select nor do_pselect");
        return;
    }
    pselect_chain.push("pselect_core");

    // ---- futex chain ----
    let wait_off = match sym(&rel, "futex_wait_requeue_pi") {
        Some(v) => v,
        None => {
            println!("futex_wait_requeue_pi MISSING -> cannot derive");
            return;
        }
    };
    let mut futex_chain = vec!["futex_wrapper"];
    if has_direct_call(&dis_by_key["futex_wrapper"], wait_off) {
        println!("futex: wrapper calls futex_wait_requeue_pi DIRECTLY");
    } else if has_direct_call(&dis_by_key["futex_wrapper"], sym(&rel, "do_futex").unwrap()) {
        println!("futex: wrapper -> do_futex -> futex_wait_requeue_pi");
        futex_chain.push("futex_dispatch");
    } else {
        println!("futex: FAIL wrapper calls neither");
        return;
    }
    futex_chain.push("futex_wait");

    for (chain, tag) in [(&pselect_chain, "pselect"), (&futex_chain, "futex")] {
        for pair in chain.windows(2) {
            let caller = pair[0];
            let callee_full = names.iter().find(|(k, _)| *k == pair[1]).unwrap().1;
            let target = sym(&rel, callee_full).unwrap();
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

    // ---- waiter local in futex_wait_requeue_pi ----
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
    if candidates.is_empty() {
        println!("no waiter candidate found; add-sp immediates in futex_wait_requeue_pi:");
        let mut counts: BTreeMap<u64, usize> = BTreeMap::new();
        for (_, imm) in add_sp_immediates(fw) {
            *counts.entry(imm).or_default() += 1;
        }
        for (imm, c) in &counts {
            println!("  0x{imm:x}: {c}");
        }
        return;
    }
    let (waiter_reg, waiter_local) = candidates[0].clone();
    let anchor =
        Regex::new(&format!(r"(?i)\badd\s+{waiter_reg},\s*sp,\s*#0x{waiter_local:x}\b")).unwrap();
    match validate_frame_live_at(fw, &anchor, "futex_wait") {
        Ok(()) => println!("waiter anchor {waiter_reg},sp,#0x{waiter_local:x}: unique + frame live OK"),
        Err(e) => println!("waiter anchor FAIL: {e}"),
    }
    for extra in [0u64, 0x18, 0x38, 0x40, 0x48] {
        let re = Regex::new(&format!(r"(?i)\[sp,\s*#0x{:x}\]", waiter_local + extra)).unwrap();
        let hits: Vec<&String> = fw.iter().filter(|l| re.is_match(l)).collect();
        println!(
            "  store [sp,#0x{:x}] (=waiter+0x{:x}): {} hits {:?}",
            waiter_local + extra,
            extra,
            hits.len(),
            hits.iter().take(2).collect::<Vec<_>>()
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
    println!(
        "buffer candidates: {:?}",
        buffer_candidates.iter().map(|v| format!("{v:#x}")).collect::<Vec<_>>()
    );
    let mut imm_counts: BTreeMap<u64, usize> = BTreeMap::new();
    for (_, imm) in &add_sp {
        *imm_counts.entry(*imm).or_default() += 1;
    }
    println!("all add-sp immediates in core_sys_select:");
    for (imm, count) in &imm_counts {
        println!("  0x{imm:x}: {count}");
    }
    println!(
        "cmp immediates in core_sys_select: {:?}",
        cmp_immediates(core).iter().map(|v| format!("0x{v:x}")).collect::<Vec<_>>()
    );

    let fds_bytes = ((PSELECT_ROUTE_NFDS + 63) / 64) * 8;
    let ok = cmp_immediates(core).iter().any(|t| fds_bytes < *t && *t <= fds_bytes + 8);
    println!("fds_bytes={fds_bytes}; stack-path threshold present: {ok}");

    // ---- math ----
    if buffer_candidates.is_empty() {
        println!("no buffer candidate -> derivation incomplete");
        return;
    }
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
        println!("   compact table (lock word 9): feasible iff derived <= 7 => {}", if shift <= 7 { "IN BAND" } else { "OUT" });
        println!("   struct-relative 5.10 (lock word 7): feasible iff derived <= 9 => {}", if shift <= 9 { "IN BAND" } else { "OUT" });
    }

    // ---- raw evidence for hand-checking ----
    println!("\n==== futex_wait_requeue_pi first 60 lines ====");
    for line in fw.iter().take(60) {
        println!("  {line}");
    }
    println!("\n==== core_sys_select first 60 lines ====");
    for line in core.iter().take(60) {
        println!("  {line}");
    }
}
