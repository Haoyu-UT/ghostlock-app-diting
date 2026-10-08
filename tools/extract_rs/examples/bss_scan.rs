//! Temporary helper — batch A of docs/analysis/payload-page-option2-plan.md.
//!
//! Lists candidate regions for `route.select_stack.lock_anchor_image`: a zero,
//! writable, reference-free kernel area the walk can use as a fake rt_mutex.
//! Prints the section bounds, then every symbol inside [__bss_start,
//! __bss_stop) whose size (distance to the next symbol) is >= min_size.
//!
//! usage: cargo run --release --example bss_scan -- <boot.img> [min_size_hex]

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use ghostlock_extract::boot::BootImage;
use ghostlock_extract::derive::relative_symbols;
use ghostlock_extract::kallsyms;
use ghostlock_extract::kallsyms_finder;

fn one(rel: &BTreeMap<String, BTreeSet<u64>>, name: &str) -> Option<u64> {
    rel.get(name).and_then(|s| s.iter().next().copied())
}

fn main() {
    let mut args = std::env::args().skip(1);
    let boot_path = args.next().unwrap_or_default();
    let min_size = args
        .next()
        .and_then(|v| u64::from_str_radix(v.trim_start_matches("0x"), 16).ok())
        .unwrap_or(0x40);

    let boot = BootImage::load(Path::new(&boot_path)).expect("load boot");
    let btf_at = boot.embedded_btf_at();
    let pair = btf_at.as_ref().map(|(o, b)| (*o, b.len()));
    let ks = kallsyms_finder::recover(&boot.kernel, pair).expect("kallsyms");
    let base = kallsyms::unique(&ks.symbols, "_text")
        .or_else(|| kallsyms::unique(&ks.symbols, "_head"))
        .expect("base");
    let (rel, _) = relative_symbols(&ks.symbols, base);

    println!("== section bounds (image-relative) ==");
    for name in [
        "_text", "_stext", "_etext", "_edata", "__bss_start", "__bss_stop",
        "__init_begin", "__init_end", "__initdata_begin", "__initdata_end",
        "_sinittext", "_einittext", "__start_ro_after_init", "__end_ro_after_init",
        "__start_rodata", "__end_rodata",
    ] {
        match one(&rel, name) {
            Some(v) => println!("  {name:<24} +0x{v:x}"),
            None => println!("  {name:<24} (absent)"),
        }
    }

    let bss_start = one(&rel, "__bss_start");
    let bss_stop = one(&rel, "__bss_stop");
    let (Some(lo), Some(hi)) = (bss_start, bss_stop) else {
        println!("\n!! __bss_start/__bss_stop not both present — cannot enumerate");
        return;
    };

    // flatten to (offset, name), sorted, dedup by offset
    let mut all: Vec<(u64, String)> = Vec::new();
    for (name, offs) in &rel {
        for o in offs {
            all.push((*o, name.clone()));
        }
    }
    all.sort();
    all.dedup_by(|a, b| a.0 == b.0);

    println!("\n== .bss symbols with size >= 0x{min_size:x} (top 40 by size) ==");
    let mut cands: Vec<(u64, u64, String)> = Vec::new(); // (size, offset, name)
    for i in 0..all.len() {
        let (off, ref name) = all[i];
        if off < lo || off >= hi {
            continue;
        }
        let next = all.get(i + 1).map(|e| e.0).unwrap_or(hi);
        let size = next.saturating_sub(off);
        if size >= min_size {
            cands.push((size, off, name.clone()));
        }
    }
    cands.sort_by(|a, b| b.0.cmp(&a.0));
    for (size, off, name) in cands.iter().take(40) {
        println!("  +0x{off:<10x} size=0x{size:<7x} {name}");
    }
    println!("\ntotal .bss symbols >= 0x{min_size:x}: {}", cands.len());
}
