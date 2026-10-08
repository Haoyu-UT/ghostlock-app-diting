//! Temporary helper — batch A of docs/analysis/payload-page-option2-plan.md.
//!
//! Finds every reference to a symbol in the kernel text by scanning for `adrp`
//! instructions whose page matches the symbol's page, then confirming the
//! low-12 offset in the following instructions and disassembling the context.
//! For each hit it prints the containing symbol and whether that symbol lives
//! in the init range (freed after boot => the reference is dead).
//!
//! usage: cargo run --release --example bss_xref -- <boot.img> <sym> [<sym>...]

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use ghostlock_extract::boot::BootImage;
use ghostlock_extract::derive::relative_symbols;
use ghostlock_extract::disasm::disassemble_range;
use ghostlock_extract::kallsyms;
use ghostlock_extract::kallsyms_finder;

fn u32_at(buf: &[u8], off: usize) -> Option<u32> {
    buf.get(off..off + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn main() {
    let mut args = std::env::args().skip(1);
    let boot_path = args.next().unwrap_or_default();
    let names: Vec<String> = args.collect();
    if names.is_empty() {
        eprintln!("usage: bss_xref <boot.img> <sym>...");
        std::process::exit(2);
    }

    let boot = BootImage::load(Path::new(&boot_path)).expect("load boot");
    let btf_at = boot.embedded_btf_at();
    let pair = btf_at.as_ref().map(|(o, b)| (*o, b.len()));
    let ks = kallsyms_finder::recover(&boot.kernel, pair).expect("kallsyms");
    let base = kallsyms::unique(&ks.symbols, "_text")
        .or_else(|| kallsyms::unique(&ks.symbols, "_head"))
        .expect("base");
    let (rel, sorted) = relative_symbols(&ks.symbols, base);

    // section bounds (image-relative)
    let g = |n: &str| rel.get(n).and_then(|s| s.iter().next().copied());
    let (tstart, tend) = (g("_text").unwrap_or(0), g("_etext").unwrap_or(0));
    let (sinit, einit) = (g("_sinittext").unwrap_or(0), g("_einittext").unwrap_or(0));

    // name lookup by offset (for "containing symbol")
    let mut by_off: Vec<(u64, String)> = Vec::new();
    for (name, offs) in &rel {
        for o in offs {
            by_off.push((*o, name.clone()));
        }
    }
    by_off.sort();
    let containing = |off: u64| -> String {
        match by_off.binary_search_by(|e| e.0.cmp(&off)) {
            Ok(i) => by_off[i].1.clone(),
            Err(0) => "(before first)".into(),
            Err(i) => format!("{} +0x{:x}", by_off[i - 1].1, off - by_off[i - 1].0),
        }
    };

    for name in &names {
        let Some(&sym) = rel.get(name).and_then(|s| s.iter().next()) else {
            println!("=== {name}: NOT FOUND ===");
            continue;
        };
        let page = sym & !0xfff;
        println!("\n=== {name} @ +0x{sym:x} (page +0x{page:x}) ===");
        let mut hits: Vec<u64> = Vec::new();
        let mut o = tstart;
        while o + 4 <= tend {
            if let Some(insn) = u32_at(&boot.kernel, o as usize) {
                if insn & 0x9f000000 == 0x90000000 {
                    let immlo = ((insn >> 29) & 3) as i64;
                    let immhi = ((insn >> 5) & 0x7ffff) as i64;
                    let mut imm = (immhi << 2) | immlo;
                    if imm & (1 << 20) != 0 {
                        imm -= 1 << 21;
                    }
                    let target = ((o & !0xfff) as i64 + (imm << 12)) as u64;
                    if target != page {
                        o += 4;
                        continue;
                    }
                    // Confirm the low-12 offset: the adrp result must be used by
                    // an add-immediate or a load/store unsigned-immediate with
                    // the symbol's offset. Without this the scan matches every
                    // symbol sharing the page (it did, on the first run).
                    let low12 = (sym & 0xfff) as u32;
                    let rd = insn & 0x1f;
                    let mut matched = false;
                    for k in 1..=4u64 {
                        if let Some(i2) = u32_at(&boot.kernel, (o + 4 * k) as usize) {
                            let rn = (i2 >> 5) & 0x1f;
                            let imm12 = (i2 >> 10) & 0xfff;
                            let kind = i2 & 0xffc00000;
                            let is_add = kind == 0x91000000;
                            let is_ldst = i2 & 0x3b000000 == 0x39000000;
                            if rn == rd && imm12 == low12 && (is_add || is_ldst) {
                                matched = true;
                                break;
                            }
                        }
                    }
                    if matched {
                        hits.push(o);
                    }
                }
            }
            o += 4;
        }
        println!("  adrp hits: {}", hits.len());
        let mut in_init = 0;
        for (i, h) in hits.iter().enumerate().take(30) {
            let who = containing(*h);
            let is_init = *h >= sinit && *h < einit;
            if is_init {
                in_init += 1;
            }
            println!("  [{i}] +0x{h:x} {} {}", if is_init { "[INIT]" } else { "[core]" }, who);
            if let Ok(lines) = disassemble_range(&boot.kernel, (*h as usize).saturating_sub(4), *h as usize + 12) {
                for l in lines {
                    println!("        {l}");
                }
            }
        }
        println!("  init-range hits: {in_init} / {}", hits.len());
    }
}
