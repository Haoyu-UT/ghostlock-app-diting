// Throwaway diagnostic (local-only, do NOT commit).
//
// Purpose: list kallsyms entries whose name matches a regex, with image
// offsets, from an image's own recovered kallsyms. Used to locate the symbols
// a candidate profile needs (cred refs, constructors, anchors) on an arbitrary
// kernel build.
//
// usage: cargo run --release --example sym_grep -- <image> <regex> [limit]

use ghostlock_extract::boot::BootImage;
use ghostlock_extract::derive::relative_symbols;
use ghostlock_extract::kallsyms;
use ghostlock_extract::kallsyms_finder;
use regex::Regex;
use std::path::Path;

fn main() {
    let mut args = std::env::args().skip(1);
    let path = args.next().expect("usage: sym_grep <image> <regex> [limit]");
    let pattern = args.next().expect("usage: sym_grep <image> <regex> [limit]");
    let limit: usize = args.next().and_then(|v| v.parse().ok()).unwrap_or(200);
    let boot = BootImage::load(Path::new(&path)).expect("load image");
    let btf_at = boot.embedded_btf_at();
    let btf_pair = btf_at.as_ref().map(|(offset, blob)| (*offset, blob.len()));
    let ks = kallsyms_finder::recover(&boot.kernel, btf_pair).expect("kallsyms");
    let base = kallsyms::unique(&ks.symbols, "_text")
        .or_else(|| kallsyms::unique(&ks.symbols, "_head"))
        .expect("base");
    let (rel, _) = relative_symbols(&ks.symbols, base);
    let re = Regex::new(&pattern).expect("bad regex");
    let mut rows: Vec<(u64, String)> = Vec::new();
    for (name, offsets) in &rel {
        if re.is_match(name) {
            for off in offsets {
                rows.push((*off, name.clone()));
            }
        }
    }
    rows.sort();
    rows.dedup();
    println!("# {} matches for {pattern:?} in {path}", rows.len());
    for (off, name) in rows.iter().take(limit) {
        println!("{off:#012x}  {name}");
    }
}
