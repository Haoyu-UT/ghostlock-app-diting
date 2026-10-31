//! Regenerate the store's option supersets: one JSON document per kernel.
//! Ignored by default; run explicitly:
//!
//! ```text
//! GHOSTLOCK_IMAGE_DIR=../../../../test-kernels \
//!     cargo test --test generate_options -- --ignored --nocapture
//! ```
//!
//! The invocation is the maximal one (every sidecar, both output flags, no
//! route forced), so ambiguous images still write the document and exit 7.

mod common;

use common::{collect_all, options_path, par_for_each, run_options};
use std::path::Path;

#[test]
#[ignore = "writes the store supersets; run explicitly with --ignored"]
fn generate_option_supersets() {
    let Some(root) = std::env::var_os("GHOSTLOCK_IMAGE_DIR") else {
        panic!("set GHOSTLOCK_IMAGE_DIR to the test-kernel store");
    };
    let binary = env!("CARGO_BIN_EXE_ghostlock-extract");
    let corpus = collect_all(Path::new(&root));
    assert!(
        !corpus.is_empty(),
        "no corpus entry under {}",
        Path::new(&root).display()
    );
    let workers = std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(4)
        .min(16);
    par_for_each(&corpus, workers, |meta| {
        let out = options_path(meta);
        let run = run_options(binary, meta, &out);
        let text = std::fs::read_to_string(&out).unwrap_or_else(|err| {
            panic!(
                "{}: no option superset: {err}\nstderr:\n{}",
                meta.release, run.stderr
            )
        });
        serde_json::from_str::<serde_json::Value>(&text).unwrap_or_else(|err| {
            panic!("{}: invalid superset JSON: {err}", meta.release)
        });
        eprintln!(
            "generated {} ({}; {} bytes)",
            meta.release,
            if run.exit == Some(7) { "ambiguous" } else { "ok" },
            text.len()
        );
    });
}
