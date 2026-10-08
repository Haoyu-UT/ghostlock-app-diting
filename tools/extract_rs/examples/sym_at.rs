//! Temporary reverse-engineering helper: name the kernel symbol containing a
//! given _text-relative offset, so call targets in a disassembly can be read.
//!
//! usage: cargo run --release --example sym_at -- <boot.img> <rel-offset>...

use std::path::Path;

use ghostlock_extract::boot::BootImage;
use ghostlock_extract::derive::relative_symbols;
use ghostlock_extract::kallsyms;
use ghostlock_extract::kallsyms_finder;

fn main() {
    let mut args = std::env::args().skip(1);
    let boot_path = args.next().unwrap_or_else(|| {
        eprintln!("usage: sym_at <boot.img> <rel-offset>...");
        std::process::exit(2);
    });
    let want: Vec<u64> = args
        .map(|a| {
            u64::from_str_radix(a.trim_start_matches("0x"), 16).expect("hex offset")
        })
        .collect();
    let boot = BootImage::load(Path::new(&boot_path)).expect("load boot image");
    let btf_at = boot.embedded_btf_at();
    let btf_pair = btf_at.as_ref().map(|(offset, blob)| (*offset, blob.len()));
    let ks = kallsyms_finder::recover(&boot.kernel, btf_pair).expect("kallsyms recovery");
    let base = kallsyms::unique(&ks.symbols, "_text")
        .or_else(|| kallsyms::unique(&ks.symbols, "_head"))
        .expect("_text/_head");
    let (_, sorted) = relative_symbols(&ks.symbols, base);
    // ks.symbols is name -> set of _text-relative offsets.
    let mut pairs: Vec<(u64, String)> = ks
        .symbols
        .iter()
        .flat_map(|(name, offsets)| {
            offsets
                .iter()
                .filter_map(move |off| Some((off.checked_sub(base)?, name.clone())))
        })
        .collect();
    pairs.sort_by_key(|(off, _)| *off);
    let _ = sorted;
    for off in want {
        let hit = pairs
            .iter()
            .rev()
            .find(|(sym_off, _)| *sym_off <= off)
            .map(|(sym_off, name)| (name.clone(), off - sym_off));
        match hit {
            Some((name, delta)) => println!("0x{off:x} -> {name}+0x{delta:x}"),
            None => println!("0x{off:x} -> <before first symbol>"),
        }
    }
}
