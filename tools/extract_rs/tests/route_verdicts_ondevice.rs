//! Route-verdict checks over a local kernel-image store.
//!
//! The images are gitignored; the test runs only when pointed at a store:
//!
//! ```text
//! GHOSTLOCK_IMAGE_DIR=../../external/test-kernels \
//!     cargo test --release --test route_verdicts_ondevice -- --nocapture
//! ```
//!
//! Expectations:
//! - every 5.10 image: `tcp_zerocopy` is Infeasible — the UAPI copy cap
//!   (0x18/0x28) ends before the route's first fake word (0x28), independent
//!   of the stack relation;
//! - every 6.1 image: Feasible (the 6.1 train matches the device-proven route);
//! - every 6.6/6.12 image: Infeasible (the relation is off by 0x10..0x38);
//! - the 6.1.138 image: `tcp_zerocopy` and `select_stack` are both Feasible,
//!   and a `--format conf` pass without `--route` exits 7 with both in the
//!   feasible report, so the app's existing dialog asks;
//! - an image whose derivation cannot run reports Unknown, never a guess.

use std::path::{Path, PathBuf};
use std::process::Command;

fn collect_images(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_images(&path, out);
        } else if let Some(name) = path.file_name().and_then(|name| name.to_str()) {
            if name.starts_with("Image-") {
                out.push(path);
            }
        }
    }
}

fn release_of(path: &Path) -> Option<String> {
    path.file_name()?
        .to_str()?
        .strip_prefix("Image-")
        .map(str::to_string)
}

fn analysis(binary: &str, image: &Path) -> String {
    let output = Command::new(binary)
        .arg(image)
        .arg("--analysis")
        .output()
        .expect("run extractor");
    assert!(
        output.status.success(),
        "{}: analysis failed: {}",
        image.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn tcp_line<'a>(text: &'a str) -> Option<&'a str> {
    text.lines()
        .find(|line| line.starts_with("route tcp_zerocopy"))
}

#[test]
fn tcp_verdicts_match_the_family_expectations() {
    let Some(dir) = std::env::var_os("GHOSTLOCK_IMAGE_DIR") else {
        eprintln!("skipping: GHOSTLOCK_IMAGE_DIR is not set");
        return;
    };
    let binary = env!("CARGO_BIN_EXE_ghostlock-extract");
    let mut images = Vec::new();
    collect_images(Path::new(&dir), &mut images);
    images.sort();

    let mut checked = 0usize;
    for image in &images {
        let Some(release) = release_of(image) else {
            continue;
        };
        let text = analysis(binary, image);
        let Some(line) = tcp_line(&text) else {
            panic!("{release}: the analysis has no tcp_zerocopy verdict line");
        };
        checked += 1;
        if release.starts_with("5.10.") {
            assert!(
                line.contains(" infeasible "),
                "{release}: 5.10 must be infeasible: {line}"
            );
        } else if release.starts_with("6.1.") {
            assert!(
                line.contains(" feasible "),
                "{release}: the 6.1 train must be feasible: {line}"
            );
        } else if release.starts_with("6.6.") || release.starts_with("6.12.") {
            assert!(
                line.contains(" infeasible "),
                "{release}: the 6.6/6.12 trains must be infeasible: {line}"
            );
        } else {
            eprintln!("note: {release}: {line}");
        }
    }
    assert!(checked > 0, "no images checked");
}

#[test]
fn the_6_1_image_asks_for_a_route_choice() {
    let Some(dir) = std::env::var_os("GHOSTLOCK_IMAGE_DIR") else {
        eprintln!("skipping: GHOSTLOCK_IMAGE_DIR is not set");
        return;
    };
    let binary = env!("CARGO_BIN_EXE_ghostlock-extract");
    let mut images = Vec::new();
    collect_images(Path::new(&dir), &mut images);
    let Some(image) = images
        .iter()
        .find(|path| release_of(path).is_some_and(|r| r.starts_with("6.1.138-")))
    else {
        eprintln!("skipping: no 6.1.138 image in the store");
        return;
    };
    let release = release_of(image).unwrap();
    let work = std::env::temp_dir().join(format!(
        "ghostlock-route-verdicts-{}-{}",
        std::process::id(),
        release
    ));
    std::fs::create_dir_all(&work).expect("temp dir");
    let out = work.join("profile.conf");
    let feasible = work.join("feasible.json");

    let first = Command::new(binary)
        .arg(image)
        .arg("--format")
        .arg("conf")
        .arg("--out")
        .arg(&out)
        .arg("--feasible-out")
        .arg(&feasible)
        .output()
        .expect("run extractor");
    assert_eq!(
        first.status.code(),
        Some(7),
        "{release}: expected the ambiguity exit: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    let report = std::fs::read_to_string(&feasible).expect("feasible report");
    assert!(
        report.contains("\"route\": \"select_stack\"")
            && report.contains("\"route\": \"tcp_zerocopy\""),
        "{release}: feasible report must carry both routes:\n{report}"
    );

    let forced = Command::new(binary)
        .arg(image)
        .arg("--format")
        .arg("conf")
        .arg("--route")
        .arg("tcp_zerocopy")
        .arg("--out")
        .arg(&out)
        .output()
        .expect("run extractor");
    assert_eq!(
        forced.status.code(),
        Some(0),
        "{release}: the forced tcp route must parse: {}",
        String::from_utf8_lossy(&forced.stderr)
    );
    let profile = std::fs::read_to_string(&out).expect("profile");
    assert!(
        profile.contains("tcp_zerocopy"),
        "{release}: the profile must select tcp_zerocopy"
    );
    let _ = std::fs::remove_dir_all(&work);
}
