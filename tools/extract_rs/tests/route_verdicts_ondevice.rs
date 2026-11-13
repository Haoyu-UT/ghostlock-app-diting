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
//! - every 6.1 image whose `tcp_zerocopy_receive` is a real symbol: Feasible
//!   (the 6.1 train matches the device-proven route); the 6.1.134 image
//!   inlines the handler and its derived relation is Infeasible;
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
            if release.starts_with("6.1.134-") {
                /* tcp_zerocopy_receive is inlined on this build; the derived
                 * relation (and the wrapper's inlined __sys_getsockopt chain)
                 * makes the route Infeasible. */
                assert!(
                    line.contains(" infeasible "),
                    "{release}: the inlined tcp_zerocopy_receive image must be \
                     infeasible: {line}"
                );
            } else {
                assert!(
                    line.contains(" feasible "),
                    "{release}: the 6.1 train must be feasible: {line}"
                );
            }
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

/// The store's device-derived ground truth for the Realme 6.1.134 image
/// (`external/test-kernels/6.1.134-…/ground-truth-routes.txt`): the tcp
/// relation is infeasible with delta -0x170 (the wrapper inlines
/// __sys_getsockopt, so that link contributes no extra frame), sigreturn is
/// feasible with waiter_off 0xE8, and the 64-bit multicast copy is too deep.
/// The compat `MCAST_BLOCK_SOURCE` copy is feasible (time64 at 0xa8 under the
/// 0x104 buffer), so the analysis now reports two feasible routes and refuses
/// to choose between them; the sidecars are passed for the maximal invocation.
#[test]
fn the_realme_6_1_image_derives_its_ground_truth() {
    let Some(dir) = std::env::var_os("GHOSTLOCK_IMAGE_DIR") else {
        eprintln!("skipping: GHOSTLOCK_IMAGE_DIR is not set");
        return;
    };
    let binary = env!("CARGO_BIN_EXE_ghostlock-extract");
    let release = "6.1.134-android14-11-o-gd252f36df142";
    let entry = Path::new(&dir).join(release);
    let image = entry.join(format!("Image-{release}"));
    if !image.is_file() {
        eprintln!("skipping: {release} is not in the store");
        return;
    }
    let sidecar = |name: &str| entry.join("devices").join("RE6022L1").join(name);
    let work = std::env::temp_dir().join(format!("ghostlock-gt-{}-{release}", std::process::id()));
    std::fs::create_dir_all(&work).expect("temp dir");
    let feasible = work.join("feasible.json");
    let mut command = Command::new(binary);
    command
        .arg(&image)
        .arg("--analysis")
        .arg("--device")
        .arg("RE6022L1")
        .arg("--feasible-out")
        .arg(&feasible);
    if sidecar("vendor_boot.img").is_file() {
        command.arg("--vendor-boot").arg(sidecar("vendor_boot.img"));
    }
    if sidecar("dtbo.img").is_file() {
        command.arg("--dtbo").arg(sidecar("dtbo.img"));
    }
    let run = command.output().expect("run extractor");
    assert!(
        run.status.success(),
        "{release}: analysis failed: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&feasible).expect("feasible report"))
            .expect("parse feasible report");
    let route = |name: &str| {
        report["routes"]
            .as_array()
            .expect("routes")
            .iter()
            .find(|entry| entry["route"] == name)
            .unwrap_or_else(|| panic!("{release}: no {name} verdict"))
    };
    assert_eq!(route("select_stack")["verdict"], "infeasible", "{release}: select");
    let multicast = route("multicast_waiter");
    assert_eq!(multicast["verdict"], "feasible", "{release}: multicast");
    assert_eq!(multicast["numbers"]["compat_carrier"], 1, "{release}: compat");
    assert_eq!(multicast["numbers"]["compat_futex_abi"], 1, "{release}: abi");
    assert_eq!(
        multicast["numbers"]["compat_waiter_off"], 0xa8,
        "{release}: compat waiter offset"
    );
    assert_eq!(
        multicast["numbers"]["compat_buffer_size"], 0x104,
        "{release}: compat buffer"
    );
    assert_eq!(
        multicast["numbers"]["copy_depth"], 0x240,
        "{release}: compat copy depth"
    );
    let sigreturn = route("sigreturn");
    assert_eq!(sigreturn["verdict"], "feasible", "{release}: sigreturn");
    assert_eq!(sigreturn["numbers"]["off_plain"], 232, "{release}: off_plain");
    assert_eq!(sigreturn["numbers"]["off_sve"], 232, "{release}: off_sve");
    let tcp = route("tcp_zerocopy");
    assert_eq!(tcp["verdict"], "infeasible", "{release}: tcp");
    assert_eq!(tcp["numbers"]["delta"], -368, "{release}: tcp delta");
    assert!(
        report["chosen"].is_null(),
        "{release}: two feasible routes must not be chosen silently: {}",
        report["chosen"]
    );
    let _ = std::fs::remove_dir_all(&work);
}

/// The duchamp 6.1.138 image is the in-hand 6.1 test device. Its 64-bit
/// multicast copy is too deep (short by 0x88 of the lock slot), but the compat
/// copy at depth 0x230 lands at 0x48 under the 0x104 buffer; there both futex
/// wrappers go through do_futex, so the home is 0x1e8 for either ABI. The
/// analysis reports four feasible routes (select, multicast compat, sigreturn,
/// tcp) and refuses to choose; the bundle's priority keeps select.
#[test]
fn the_duchamp_6_1_image_derives_the_compat_multicast_geometry() {
    let Some(dir) = std::env::var_os("GHOSTLOCK_IMAGE_DIR") else {
        eprintln!("skipping: GHOSTLOCK_IMAGE_DIR is not set");
        return;
    };
    let binary = env!("CARGO_BIN_EXE_ghostlock-extract");
    let release = "6.1.138-android14-11-g44bda9e8f6e9-ab13792638";
    let entry = Path::new(&dir).join(release);
    let image = entry.join(format!("Image-{release}"));
    if !image.is_file() {
        eprintln!("skipping: {release} is not in the store");
        return;
    }
    let work = std::env::temp_dir().join(format!("ghostlock-gt-{}-{release}", std::process::id()));
    std::fs::create_dir_all(&work).expect("temp dir");
    let feasible = work.join("feasible.json");
    let run = Command::new(binary)
        .arg(&image)
        .arg("--analysis")
        .arg("--feasible-out")
        .arg(&feasible)
        .output()
        .expect("run extractor");
    assert!(
        run.status.success(),
        "{release}: analysis failed: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&feasible).expect("feasible report"))
            .expect("parse feasible report");
    let route = |name: &str| {
        report["routes"]
            .as_array()
            .expect("routes")
            .iter()
            .find(|entry| entry["route"] == name)
            .unwrap_or_else(|| panic!("{release}: no {name} verdict"))
    };
    assert_eq!(route("select_stack")["verdict"], "feasible", "{release}: select");
    let multicast = route("multicast_waiter");
    assert_eq!(multicast["verdict"], "feasible", "{release}: multicast");
    assert_eq!(multicast["numbers"]["compat_carrier"], 1, "{release}: compat");
    assert_eq!(multicast["numbers"]["compat_futex_abi"], 1, "{release}: abi");
    assert_eq!(
        multicast["numbers"]["compat_waiter_off"], 0x48,
        "{release}: compat waiter offset"
    );
    assert_eq!(
        multicast["numbers"]["compat_buffer_size"], 0x104,
        "{release}: compat buffer"
    );
    assert_eq!(
        multicast["numbers"]["copy_depth"], 0x230,
        "{release}: compat copy depth"
    );
    assert_eq!(
        multicast["numbers"]["source_overlap"], 1,
        "{release}: source header overlap"
    );
    assert!(
        report["chosen"].is_null(),
        "{release}: multiple feasible routes must not be chosen silently: {}",
        report["chosen"]
    );
    let _ = std::fs::remove_dir_all(&work);
}
