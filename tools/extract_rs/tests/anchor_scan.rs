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
    let g = |n: &str| {
        rel.get(n)
            .and_then(|s| s.iter().next().copied())
            .unwrap_or(0)
    };
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
    assert_eq!(
        a.safe_len, ANCHOR_BYTES,
        "safe length (the array, one page)"
    );

    /* `dump_skip()` reads the region as the source of a bulk copy, so it is not
     * reference-free -- and the tool must say so rather than call it safe. The
     * copy's read is not a constant-offset load: the address is materialised
     * into the kvec and consumed by a generic copy, so the 2026-10-27 scanner
     * fixes correctly stopped reporting the old `live_read` hits for this
     * symbol as false positives (ABI-blind register tracking). The distinction
     * is therefore carried by the materialisations and the NeedsReview
     * verdict; `Safe` here would still mean the tool lost it. */
    assert_eq!(a.verdict, Verdict::NeedsReview, "verdict");
    assert!(a.live_writes.is_empty(), "no live writes into the anchor");
    assert!(
        !a.materializations.is_empty(),
        "the copy source is materialised"
    );
    assert!(
        a.live_reads.is_empty(),
        "the old false-positive reads stay retired"
    );
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
     * in the kernel, but printk writes it through indexes the static scan
     * cannot see. The scan therefore reports no live writes and a `Safe`
     * verdict -- which is exactly why the *selector* must not use the verdict
     * (dd10f34a): a ranked "largest safe candidate" rule picked this 128 KiB
     * buffer over the 4 KiB coredump zero page on 6.12.23. Selection is
     * restricted to the named, device-proven regions instead. */
    let cand = anchor::Candidate {
        name: "__log_buf".to_string(),
        offset: rel
            .get("__log_buf")
            .and_then(|s| s.iter().next().copied())
            .expect("__log_buf present"),
        extent: 0x20000,
    };
    let a = anchor::assess(&cand, &refs, &rel, &b);
    assert!(
        a.live_writes.is_empty(),
        "the scan cannot see printk's indexed writes"
    );
    assert_eq!(
        a.verdict,
        Verdict::Safe,
        "the scan alone cannot refuse it; the selector must"
    );

    /* The production 5.10 preference list never offers __log_buf, and the
     * named pick is the coredump zero page -- smaller than the buffer a ranked
     * rule would have chosen. */
    let pick = anchor::select_candidate(
        &kernel,
        &rel,
        &[
            "__dump_skip.zeroes",
            "dump_skip.zeroes",
            "s3c24xx_serial_ports",
        ],
    );
    let selected = pick.selected.expect("the named zero page is selected");
    assert_eq!(selected.candidate.name, "dump_skip.zeroes");
    assert!(
        selected.safe_len < a.safe_len,
        "the refused buffer is the larger one the ranked rule would have taken"
    );
}
