//! The cut and the CLI must materialize the same profile.
//!
//! `--format conf --anchor` follows the auto plan (`options::auto_plan`); the
//! cut renders the same plan from the stored superset. If they disagree, the
//! app and the CLI would run different configurations from one derivation.
//!
//! The samples cover the three plan shapes: in-anchor (5.10.236, 6.6.66),
//! second region (6.1.138), and page with an anchor only (5.10.101).

mod common;

use common::{blocks, collect_all, options_path, run_auto_conf};
use std::path::Path;

fn compare(superset: &serde_json::Value, route: &str, conf: &str, release: &str) {
    let golden = ghostlock_extract::options::Superset::from_value(superset)
        .unwrap_or_else(|err| panic!("{release}: golden superset: {err}"));
    let cut = ghostlock_extract::options::cut(&golden, route, ghostlock_extract::options::PlanKind::Auto)
        .unwrap_or_else(|| panic!("{release}: no auto cut"));
    let want = blocks(&cut);
    let got = blocks(conf);
    for block in [
        "route",
        "task_struct",
        "cred",
        "kernelsnitch",
        "offset",
        "waiter_layout",
        "selinux",
        "w1_scratch",
    ] {
        assert_eq!(
            want.get(block),
            got.get(block),
            "{release}: cut and CLI disagree on {block}"
        );
    }
}

#[test]
fn cut_matches_the_cli_default() {
    let Some(image_dir) = std::env::var_os("GHOSTLOCK_IMAGE_DIR") else {
        eprintln!("skipping: GHOSTLOCK_IMAGE_DIR is not set");
        return;
    };
    let binary = env!("CARGO_BIN_EXE_ghostlock-extract");
    let corpus = collect_all(Path::new(&image_dir));
    let samples = [
        ("5.10.236-android12-9-00003-gfb24cf99ad97-ab14313284", "select_stack", "in-anchor"),
        ("6.6.66-android15-8-g29d86c5fc9dd-abogki428889875-4k", "select_stack", "in-anchor"),
        ("6.1.138-android14-11-g44bda9e8f6e9-ab13792638", "select_stack", "second region"),
        ("5.10.101-android12-9-00005-ga829d48e78bd-ab9206161", "sigreturn", "page"),
    ];
    let mut checked = 0;
    for (prefix, route, kind) in samples {
        let Some(meta) = corpus.iter().find(|meta| meta.release.starts_with(prefix)) else {
            eprintln!("skip {prefix}: not in the corpus");
            continue;
        };
        let golden: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(options_path(meta)).expect("read superset"),
        )
        .expect("parse superset");
        let run = run_auto_conf(binary, meta, route);
        assert_eq!(run.exit, Some(0), "{}: conf run failed\n{}", meta.release, run.stderr);
        eprintln!("ok {}: cut == CLI ({kind})", meta.release);
        compare(&golden, route, &run.stdout, &meta.release);
        checked += 1;
    }
    assert!(checked > 0, "no sample was checked");
}
