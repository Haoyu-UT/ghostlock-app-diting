//! The cut and the CLI must materialize the same profile.
//!
//! `--format conf --anchor` follows the auto plan (`options::auto_plan`); the
//! cut renders the same plan from the stored superset. If they disagree, the
//! app and the CLI would run different configurations from one derivation.
//!
//! The samples cover the three plan shapes: in-anchor (5.10.236, 6.6.66),
//! second region (6.1.138), and page with an anchor only (5.10.101).

mod common;

use common::{blocks, collect_all, options_path, run_auto_conf, run_auto_conf_for};
use std::path::Path;

fn compare(superset: &serde_json::Value, route: &str, conf: &str, release: &str, device: Option<&str>) {
    let golden = ghostlock_extract::options::Superset::from_value(superset)
        .unwrap_or_else(|err| panic!("{release}: golden superset: {err}"));
    let cut = ghostlock_extract::options::cut_with_device(
        &golden,
        route,
        ghostlock_extract::options::PlanKind::Auto,
        device,
    )
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
        ("5.10.101-android12-9-00001-gf4c0e37dbcde-ab8596533", "sigreturn", "yunluo device"),
        ("5.10.168-android12-9-00001-g81e7418c6466-ab10486262", "select_stack", "rubens device"),
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
        compare(&golden, route, &run.stdout, &meta.release, meta.device.as_deref());
        checked += 1;
    }
    assert!(checked > 0, "no sample was checked");
}

#[test]
fn every_sidecar_device_cut_matches_the_cli() {
    let Some(image_dir) = std::env::var_os("GHOSTLOCK_IMAGE_DIR") else {
        eprintln!("skipping: GHOSTLOCK_IMAGE_DIR is not set");
        return;
    };
    let binary = env!("CARGO_BIN_EXE_ghostlock-extract");
    let corpus = collect_all(Path::new(&image_dir));
    for release in [
        "5.10.198-android12-9-00085-g226a9632f13d-ab11136126",
        "5.10.209-android12-9-00019-g4ea09a298bb4-ab12292661",
    ] {
        let Some(meta) = corpus.iter().find(|meta| meta.release == release) else {
            eprintln!("skip {release}: not in the corpus");
            continue;
        };
        assert_eq!(
            meta.devices,
            vec![
                "diting".to_string(),
                "yunluo".to_string(),
                "rubens".to_string(),
                "matisse".to_string(),
            ],
            "{release}: device sidecar sets"
        );
        let golden: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(options_path(meta)).expect("read superset"),
        )
        .expect("parse superset");
        for device in &meta.devices {
            let run = run_auto_conf_for(binary, meta, "select_stack", Some(device));
            assert_eq!(
                run.exit,
                Some(0),
                "{release} {device}: conf run failed\n{}",
                run.stderr
            );
            compare(&golden, "select_stack", &run.stdout, release, Some(device));
            let expected_load = if device == "diting" {
                2818572288u64
            } else {
                1073741824u64
            };
            assert!(
                run.stdout.contains(&format!(
                    "kernel_phys_load = {{ {device} = {expected_load} }}"
                )),
                "{release} {device}: missing the device pair\n{}",
                run.stdout
            );
            if device != "diting" {
                assert!(
                    run.stdout.contains(&format!(
                        "kernel_phys_offset = {{ {device} = 1073741824 }}"
                    )),
                    "{release} {device}: missing the device offset\n{}",
                    run.stdout
                );
            }
        }
    }
}

#[test]
fn device_cut_carries_the_physical_map() {
    let Some(image_dir) = std::env::var_os("GHOSTLOCK_IMAGE_DIR") else {
        eprintln!("skipping: GHOSTLOCK_IMAGE_DIR is not set");
        return;
    };
    let binary = env!("CARGO_BIN_EXE_ghostlock-extract");
    let corpus = collect_all(Path::new(&image_dir));
    let release = "5.10.101-android12-9-00001-gf4c0e37dbcde-ab8596533";
    let Some(meta) = corpus.iter().find(|meta| meta.release == release) else {
        eprintln!("skip {release}: not in the corpus");
        return;
    };
    assert_eq!(meta.device.as_deref(), Some("yunluo"), "{release}: meta device");
    let run = run_auto_conf(binary, meta, "sigreturn");
    assert_eq!(run.exit, Some(0), "{}: conf run failed\n{}", meta.release, run.stderr);
    let conf = &run.stdout;
    assert!(conf.contains("schema_version = 2"), "{conf}");
    assert!(
        conf.contains("kernel_phys_load = { yunluo = 1073741824 }"),
        "{conf}"
    );
    assert!(
        conf.contains("kernel_phys_offset = { yunluo = 1073741824 }"),
        "{conf}"
    );
    assert!(conf.contains("device=yunluo;"), "{conf}");
    /* The compiled MTK default is not a witness; the cut must not carry it. */
    assert!(!conf.contains("kernel_phys_load = 2147483648"), "{conf}");
}

#[test]
fn rubens_device_cut_carries_the_physical_map() {
    let Some(image_dir) = std::env::var_os("GHOSTLOCK_IMAGE_DIR") else {
        eprintln!("skipping: GHOSTLOCK_IMAGE_DIR is not set");
        return;
    };
    let binary = env!("CARGO_BIN_EXE_ghostlock-extract");
    let corpus = collect_all(Path::new(&image_dir));
    let release = "5.10.168-android12-9-00001-g81e7418c6466-ab10486262";
    let Some(meta) = corpus.iter().find(|meta| meta.release == release) else {
        eprintln!("skip {release}: not in the corpus");
        return;
    };
    assert_eq!(meta.device.as_deref(), Some("rubens"), "{release}: meta device");
    let run = run_auto_conf(binary, meta, "select_stack");
    assert_eq!(run.exit, Some(0), "{}: conf run failed\n{}", meta.release, run.stderr);
    let conf = &run.stdout;
    assert!(conf.contains("schema_version = 2"), "{conf}");
    assert!(
        conf.contains("kernel_phys_load = { rubens = 1073741824 }"),
        "{conf}"
    );
    assert!(
        conf.contains("kernel_phys_offset = { rubens = 1073741824 }"),
        "{conf}"
    );
    assert!(conf.contains("device=rubens;"), "{conf}");
}
