//! The store's option supersets: one document per kernel, compared whole.
//!
//! ```text
//! GHOSTLOCK_IMAGE_DIR=../../../../test-kernels \
//!     cargo test --test options_ondevice -- --nocapture
//! ```
//!
//! The invocation is maximal: every sidecar the entry carries, both output
//! flags, no route forced. The expected file is `options-<release>.json` — the
//! single golden per kernel, holding every feasible route with its geometry,
//! every named anchor candidate with its page-free placement, the page/auto/
//! attested plans, and the route-less common profile blocks. Ambiguous images
//! exit 7 after writing it, so both exit codes are accepted.
//!
//! Family-specific behaviour that is not data (the BTF contradiction warnings
//! and the no-disassembly leak control) stays asserted here, on top.

mod common;

use common::{blocks, collect_all, options_path, par_for_each, run_no_disasm, run_options};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

fn check_entry(binary: &str, meta: &common::Meta, checked: &AtomicUsize) {
    let release = &meta.release;
    let golden = options_path(meta);
    let want: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&golden).unwrap_or_else(|err| {
            panic!(
                "{release}: cannot read {}: {err}",
                golden.display()
            )
        }),
    )
    .expect("parse golden superset");
    let out = std::env::temp_dir().join(format!(
        "gl-options-{}-{}.json",
        std::process::id(),
        release
    ));
    let run = run_options(binary, meta, &out);
    assert!(
        matches!(run.exit, Some(0) | Some(7)),
        "{release}: extractor failed (exit {:?})\n{}",
        run.exit,
        run.stderr
    );
    let got: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out).expect("read produced superset"))
            .expect("parse produced superset");
    let _ = std::fs::remove_file(&out);

    /* Section-first so a failure names the part that moved. */
    for key in ["schema_version", "release", "kernel_major", "kernel_phys_load",
                "kernel_phys_offset", "routes", "candidates", "plans", "profile", "chosen"] {
        assert_eq!(
            want.get(key),
            got.get(key),
            "{release}: superset section {key:?} differs"
        );
    }
    assert_eq!(want, got, "{release}: superset differs");

    /* Family behaviour that the document cannot carry. */
    if release.starts_with("6.6.66-") {
        assert!(
            run.stderr.contains("BTF cred.usage is 8"),
            "{release}: missing the BTF-usage warning\n{}",
            run.stderr
        );
        assert!(
            run.stderr.contains("BTF cred.uid is at +8"),
            "{release}: missing the BTF-uid warning\n{}",
            run.stderr
        );
    }
    if release.starts_with("6.1.138-") {
        assert!(
            run.stderr.contains("BTF cred.security is +120"),
            "{release}: missing the BTF-security warning\n{}",
            run.stderr
        );
        assert!(
            run.stderr.contains("BTF cred cap_inheritable is +40"),
            "{release}: missing the BTF-caps warning\n{}",
            run.stderr
        );
    }

    /* The no-disassembly control: forcing it must not plant a foreign-family
     * anchor. Compare the one key that historically leaked. */
    let route = want["routes"]
        .as_array()
        .and_then(|routes| {
            routes
                .iter()
                .find(|route| route["verdict"] == "feasible")
                .and_then(|route| route["route"].as_str())
        })
        .unwrap_or("select_stack");
    let control = run_no_disasm(binary, meta, route);
    assert_eq!(
        control.exit,
        Some(0),
        "{release}: --no-disasm failed\n{}",
        control.stderr
    );
    let want_anchor = want["profile"]["offset"]["slide_loggers_0_1"].as_str();
    let got_anchor = blocks(&control.stdout)
        .get("offset")
        .and_then(|lines| {
            lines
                .iter()
                .find(|line| line.starts_with("slide_loggers_0_1"))
        })
        .and_then(|line| line.split_once('='))
        .map(|(_, value)| value.trim().to_string());
    if let (Some(want_anchor), Some(got_anchor)) = (want_anchor, got_anchor) {
        assert_eq!(
            got_anchor, want_anchor,
            "{release}: --no-disasm emitted a foreign loggers anchor\n{}",
            control.stderr
        );
    }

    checked.fetch_add(1, Ordering::Relaxed);
}

#[test]
fn option_supersets_match_the_store() {
    let Some(image_dir) = std::env::var_os("GHOSTLOCK_IMAGE_DIR") else {
        eprintln!("skipping: GHOSTLOCK_IMAGE_DIR is not set");
        return;
    };
    let binary = env!("CARGO_BIN_EXE_ghostlock-extract");
    let corpus = collect_all(Path::new(&image_dir));
    assert!(
        !corpus.is_empty(),
        "no corpus entry under {}",
        Path::new(&image_dir).display()
    );
    let workers = std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(4)
        .min(16);
    let checked = AtomicUsize::new(0);
    par_for_each(&corpus, workers, |meta| check_entry(binary, meta, &checked));
    assert!(
        checked.load(Ordering::Relaxed) > 0,
        "no option superset was checked"
    );
}
