//! Analysis helper: every anchor candidate, not only the top five by extent.
//!
//! `--anchor-scan` prints the five largest candidates by extent, which hides
//! smaller regions -- e.g. one outside an active driver's dense `.bss` block.
//! This example runs the same derivation `src/main.rs`'s `anchor_scan()` runs
//! (`anchor::candidates` + `anchor::scan_references` + `anchor::assess`) over
//! **every** candidate and prints one line per candidate, sorted by verdict
//! then safe length, plus the top 20 overall by safe length.
//!
//! usage: cargo run --release --example anchor_all -- <Image> [min_extent]
//!
//! `min_extent` accepts decimal or `0x`-prefixed hex; the default is 256, the
//! scan's own default.

use std::path::Path;

use ghostlock_extract::anchor;
use ghostlock_extract::boot::BootImage;
use ghostlock_extract::derive::relative_symbols;
use ghostlock_extract::kallsyms;
use ghostlock_extract::kallsyms_finder;

fn rank(verdict: anchor::Verdict) -> u8 {
    match verdict {
        anchor::Verdict::Safe => 0,
        anchor::Verdict::NeedsReview => 1,
        anchor::Verdict::Unsafe => 2,
    }
}

fn parse_u64(text: &str) -> u64 {
    let text = text.trim();
    match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16).expect("hex min_extent"),
        None => text.parse().expect("decimal min_extent"),
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let boot_path = args.next().unwrap_or_default();
    let min_extent = args.next().map(|v| parse_u64(&v)).unwrap_or(256);
    if boot_path.is_empty() {
        eprintln!("usage: anchor_all <Image> [min_extent]");
        std::process::exit(2);
    }

    let boot = BootImage::load(Path::new(&boot_path)).expect("load boot image");
    let btf_at = boot.embedded_btf_at();
    let btf_pair = btf_at.as_ref().map(|(offset, blob)| (*offset, blob.len()));
    let ks = kallsyms_finder::recover(&boot.kernel, btf_pair).expect("recover kallsyms");
    let base = kallsyms::unique(&ks.symbols, "_text")
        .or_else(|| kallsyms::unique(&ks.symbols, "_head"))
        .expect("_text/_head unique");
    let (rel, _sorted_offsets) = relative_symbols(&ks.symbols, base);

    // Same construction as `anchor_scan()` in src/main.rs (and anchor::bounds_from):
    // each section symbol's lowest recovered offset, zero when absent.
    let g = |n: &str| rel.get(n).and_then(|s| s.iter().next().copied()).unwrap_or(0);
    let bounds = anchor::Bounds {
        text_start: g("_text"),
        text_end: g("_etext"),
        init_start: g("_sinittext"),
        init_end: g("_einittext"),
        bss_start: g("__bss_start"),
        bss_end: g("__bss_stop"),
        ro_after_init_end: g("__end_ro_after_init"),
    };

    println!(
        "[anchor-all] image {}  base 0x{:x}  min_extent 0x{:x}",
        boot_path, base, min_extent
    );
    println!(
        "[anchor-all] .bss [+0x{:x}, +0x{:x}), writable from +0x{:x}; \
text [+0x{:x}, +0x{:x}), init [+0x{:x}, +0x{:x})",
        bounds.bss_start,
        bounds.bss_end,
        bounds.ro_after_init_end,
        bounds.text_start,
        bounds.text_end,
        bounds.init_start,
        bounds.init_end,
    );

    let cands = anchor::candidates(&rel, &bounds, min_extent);
    if cands.is_empty() {
        println!("[anchor-all] no candidate symbols in writable .bss");
        return;
    }

    let refs = anchor::scan_references(&boot.kernel, &bounds);
    let mut assessed: Vec<anchor::Assessment> = cands
        .iter()
        .map(|cand| anchor::assess(cand, &refs, &rel, &bounds))
        .collect();

    let safe = assessed
        .iter()
        .filter(|a| a.verdict == anchor::Verdict::Safe)
        .count();
    let needs_review = assessed
        .iter()
        .filter(|a| a.verdict == anchor::Verdict::NeedsReview)
        .count();
    let unsafe_ = assessed
        .iter()
        .filter(|a| a.verdict == anchor::Verdict::Unsafe)
        .count();
    println!(
        "[anchor-all] {} candidate symbol(s); {} direct reference(s); \
{} safe, {} needs-review, {} unsafe\n",
        assessed.len(),
        refs.len(),
        safe,
        needs_review,
        unsafe_
    );

    // Verdict first, then longest safe region: the reviewable rows surface.
    assessed.sort_by(|a, b| {
        rank(a.verdict)
            .cmp(&rank(b.verdict))
            .then(b.safe_len.cmp(&a.safe_len))
            .then(a.candidate.offset.cmp(&b.candidate.offset))
    });

    println!("== every candidate: verdict, then safe_len descending ==");
    for a in &assessed {
        println!(
            "{:<10} {:<48} image +0x{:<9x} extent 0x{:<7x} safe_len 0x{:<7x} \
first {:<8} mats {:<3} reads {:<3} writes {:<3} init {:<3} stopped_by {}",
            a.verdict.label(),
            a.candidate.name,
            a.candidate.offset,
            a.candidate.extent,
            a.safe_len,
            a.first_access.map(|v| format!("0x{v:x}")).unwrap_or_else(|| "none".into()),
            a.materializations.len(),
            a.live_reads.len(),
            a.live_writes.len(),
            a.init_refs.len(),
            a.stopped_by,
        );
    }

    // The verdict is "live reads exist", so name each read for the review.
    println!("\n== needs-review candidates: live reads ==");
    let mut any_reads = false;
    for a in assessed
        .iter()
        .filter(|a| a.verdict == anchor::Verdict::NeedsReview)
    {
        any_reads = true;
        println!(
            "[anchor-all] needs-review {}  image +0x{:x}  extent 0x{:x}  \
safe_len 0x{:x}  stopped_by {}",
            a.candidate.name,
            a.candidate.offset,
            a.candidate.extent,
            a.safe_len,
            a.stopped_by,
        );
        for r in &a.live_reads {
            println!(
                "  read target +0x{:x} width {} at text +0x{:x}",
                r.target, r.width, r.site,
            );
        }
    }
    if !any_reads {
        println!("(none)");
    }

    let mut by_len: Vec<&anchor::Assessment> = assessed.iter().collect();
    by_len.sort_by(|a, b| {
        b.safe_len
            .cmp(&a.safe_len)
            .then(rank(a.verdict).cmp(&rank(b.verdict)))
            .then(a.candidate.offset.cmp(&b.candidate.offset))
    });
    println!("\n== top 20 by safe_len, all verdicts ==");
    for (i, a) in by_len.iter().take(20).enumerate() {
        println!(
            "{:>2}. {:<10} {:<48} image +0x{:<9x} extent 0x{:<7x} safe_len 0x{:<7x} \
first {:<8} mats {:<3} reads {:<3} writes {:<3} stopped_by {}",
            i + 1,
            a.verdict.label(),
            a.candidate.name,
            a.candidate.offset,
            a.candidate.extent,
            a.safe_len,
            a.first_access.map(|v| format!("0x{v:x}")).unwrap_or_else(|| "none".into()),
            a.materializations.len(),
            a.live_reads.len(),
            a.live_writes.len(),
            a.stopped_by,
        );
    }
}
