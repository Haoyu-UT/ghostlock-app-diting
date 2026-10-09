//! Acceptance test for `--anchor-scan`.
//!
//! The device image is 192 MB and gitignored, so this runs only when pointed at
//! one:
//!
//! ```text
//! GHOSTLOCK_BOOT_IMG=external/boot.img cargo test --test anchor_scan -- --nocapture
//! ```
//!
//! What makes this a test rather than a tautology: the expected numbers were
//! **measured on the device**, not produced by the tools this module absorbs.
//! The kprobe footprint showed only `+0x08` and `+0x10` of a used slot ever
//! written and nothing past `+0x18` (where the stride's 0x20 comes from), and a
//! rotation of one page reaches `kernfs_pr_cont_buf` (where the length's 0x1000
//! comes from). Asserting against `bss_scan`/`bss_xref`'s output would prove
//! nothing, since the new code shares their ancestry.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use ghostlock_extract::anchor::{self, Verdict};
use ghostlock_extract::boot::BootImage;
use ghostlock_extract::derive::relative_symbols;
use ghostlock_extract::kallsyms;
use ghostlock_extract::kallsyms_finder;

/// The anchor this port ships, and the values measured on the device.
const ANCHOR_SYMBOL: &str = "dump_skip.zeroes";
const ANCHOR_OFFSET: u64 = 0x2a3a590;
const ANCHOR_BYTES: u64 = 0x1000;

fn load() -> Option<(Vec<u8>, BTreeMap<String, BTreeSet<u64>>)> {
    let path = std::env::var("GHOSTLOCK_BOOT_IMG").ok()?;
    let boot = BootImage::load(Path::new(&path)).expect("load boot image");
    let btf_at = boot.embedded_btf_at();
    let pair = btf_at.as_ref().map(|(o, b)| (*o, b.len()));
    let ks = kallsyms_finder::recover(&boot.kernel, pair).expect("kallsyms");
    let base = kallsyms::unique(&ks.symbols, "_text")
        .or_else(|| kallsyms::unique(&ks.symbols, "_head"))
        .expect("_text/_head");
    let (rel, _) = relative_symbols(&ks.symbols, base);
    Some((boot.kernel, rel))
}

fn bounds(rel: &BTreeMap<String, BTreeSet<u64>>) -> anchor::Bounds {
    let g = |n: &str| rel.get(n).and_then(|s| s.iter().next().copied()).unwrap_or(0);
    anchor::Bounds {
        text_start: g("_text"),
        text_end: g("_etext"),
        init_start: g("_sinittext"),
        init_end: g("_einittext"),
        bss_start: g("__bss_start"),
        bss_end: g("__bss_stop"),
        ro_after_init_end: g("__end_ro_after_init"),
    }
}

#[test]
fn reproduces_the_device_measurement() {
    let Some((kernel, rel)) = load() else {
        eprintln!("skipped: set GHOSTLOCK_BOOT_IMG to a boot.img to run this");
        return;
    };
    let b = bounds(&rel);
    let cands = anchor::candidates(&rel, &b, 0x100);
    let refs = anchor::scan_references(&kernel, &b);

    /* The scan has to be finding real accesses. An early version filtered each
     * hit on "target is inside the text range", which discarded every reference
     * into .bss -- the ones that matter -- and left 667 hits from function
     * pointer tables. Anything in the thousands is a scan that is actually
     * looking at data. */
    assert!(
        refs.len() > 10_000,
        "only {} references found; the scan is not seeing data accesses",
        refs.len()
    );

    let cand = cands
        .iter()
        .find(|c| c.name == ANCHOR_SYMBOL)
        .expect("anchor symbol present in .bss");
    assert_eq!(cand.offset, ANCHOR_OFFSET, "anchor offset");

    let a = anchor::assess(cand, &refs, &rel, &b);
    assert_eq!(a.safe_len, ANCHOR_BYTES, "safe length (the array, one page)");

    /* `dump_skip()` reads the region as the source of a bulk copy, so it is not
     * reference-free -- and the tool must say so rather than call it safe. If
     * this ever becomes `Safe`, the tool has lost a distinction, not gained
     * one. */
    assert_eq!(a.verdict, Verdict::NeedsReview, "verdict");
    assert!(a.live_writes.is_empty(), "no live writes into the anchor");
    assert!(!a.live_reads.is_empty(), "the copy source is found");
}

#[test]
fn rejects_the_kernel_log_buffer() {
    let Some((kernel, rel)) = load() else {
        eprintln!("skipped: set GHOSTLOCK_BOOT_IMG to a boot.img to run this");
        return;
    };
    let b = bounds(&rel);
    let refs = anchor::scan_references(&kernel, &b);

    /* `__log_buf` is the printk ring buffer: one of the most written-to objects
     * in the kernel. A scan that calls it usable is worse than no scan, and an
     * earlier version of this one did exactly that. */
    let cand = anchor::Candidate {
        name: "__log_buf".to_string(),
        offset: rel
            .get("__log_buf")
            .and_then(|s| s.iter().next().copied())
            .expect("__log_buf present"),
        extent: 0x20000,
    };
    let a = anchor::assess(&cand, &refs, &rel, &b);
    assert_eq!(a.verdict, Verdict::Unsafe, "__log_buf must be unsafe");
    assert!(!a.live_writes.is_empty(), "its live writes are found");
}
