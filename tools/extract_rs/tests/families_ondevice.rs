//! Cross-family checks on kernels outside the 5.10 series.
//!
//! The 5.10 no-BTF derivation is family-specific; these images exercise the
//! BTF path, the route derivation and — most importantly — the family gates.
//! The images are gitignored, so the test runs only when pointed at a store:
//!
//! ```text
//! GHOSTLOCK_IMAGE_DIR=../../external/test-kernels \
//!     cargo test --test families_ondevice -- --nocapture
//! ```
//!
//! For every `Image-5.15.*` / `Image-6.1.*` / `Image-6.6.*` / `Image-6.12.*`
//! with a golden profile — the bundled asset when the release has one, else
//! the image directory's `profile.conf` or first `profile-<route>.conf` (the
//! 2026-10-29 QEMU corpus writes those) — the test renders the profile with
//! that route and compares every non-null field against the image. It then
//! forces `--no-disasm` and checks that no 5.10-only fallback leaks into
//! another family: the `loggers` anchor must match the golden value or be
//! absent.
//!
//! An image without any golden is skipped with a message. Since 2026-10-29 the
//! QEMU corpus supplies a golden for every 5.15/6.x entry except the patched
//! 6.12.69; see `external/test-kernels/README.md` for the provenance tiers.

use std::collections::BTreeMap;
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
            let cross_family = ["Image-5.15.", "Image-6.1.", "Image-6.6.", "Image-6.12."]
                .iter()
                .any(|prefix| name.starts_with(prefix));
            if cross_family {
                out.push(path);
            }
        }
    }
}

/// Flatten a HOCON profile into `block.path.key = value`, resolving includes
/// relative to `dir`. Later assignments override earlier ones, so a profile
/// body overrides the values its includes carry.
fn parse_text(text: &str, dir: &Path, out: &mut BTreeMap<String, String>) {
    let mut stack: Vec<String> = Vec::new();
    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("include ") {
            let name = rest.trim().trim_matches('"');
            let path = dir.join(name);
            if let Ok(included) = std::fs::read_to_string(&path) {
                parse_text(&included, dir, out);
            }
            continue;
        }
        if line == "}" {
            stack.pop();
            continue;
        }
        if let Some(rest) = line.strip_suffix('{') {
            stack.push(rest.trim().to_string());
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            let mut path = stack.join(".");
            if !path.is_empty() {
                path.push('.');
            }
            path.push_str(key.trim());
            out.insert(path, value.trim().to_string());
        }
    }
}

fn parse_profile(path: &Path, out: &mut BTreeMap<String, String>) {
    if let Ok(text) = std::fs::read_to_string(path) {
        parse_text(&text, path.parent().unwrap_or(Path::new(".")), out);
    }
}

fn run(binary: &str, image: &Path, route: &str, no_disasm: bool) -> (i32, String, String) {
    let mut command = Command::new(binary);
    command
        .arg(image)
        .arg("--format")
        .arg("conf")
        .arg("--route")
        .arg(route);
    if no_disasm {
        command.arg("--no-disasm");
    }
    let output = command.output().expect("run extractor");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn primary_route(profile: &BTreeMap<String, String>) -> Option<String> {
    profile
        .keys()
        .find_map(|key| key.strip_prefix("route."))
        .and_then(|rest| rest.split('.').next())
        .map(str::to_string)
}

#[test]
fn cross_family_profiles_match_the_bundled_truth() {
    let Some(image_dir) = std::env::var_os("GHOSTLOCK_IMAGE_DIR") else {
        eprintln!("skipping: GHOSTLOCK_IMAGE_DIR is not set");
        return;
    };
    let assets =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../app/src/main/assets/kernel_profiles");
    let binary = env!("CARGO_BIN_EXE_ghostlock-extract");
    let mut images = Vec::new();
    collect_images(Path::new(&image_dir), &mut images);
    images.sort();

    let mut checked = 0usize;
    let mut expected = 0usize;
    for image in &images {
        let release = image
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_prefix("Image-"))
            .expect("Image-<release> file name")
            .to_string();
        // The bundled asset is the app's truth; when there is none, an
        // image-dir golden (`profile.conf`, else the first route-specific one)
        // is the ground truth. This is how the device-gated CPH2723 6.6.66
        // page profile and the myron 6.12.23 export are exercised.
        let mut golden = assets.join(format!("{release}.conf"));
        if !golden.is_file() {
            let dir = image.parent().unwrap_or(Path::new("."));
            let primary = dir.join("profile.conf");
            golden = if primary.is_file() {
                primary
            } else {
                let mut route_profiles: Vec<PathBuf> = std::fs::read_dir(dir)
                    .map(|entries| {
                        entries
                            .flatten()
                            .map(|entry| entry.path())
                            .filter(|path| {
                                path.file_name()
                                    .and_then(|name| name.to_str())
                                    .is_some_and(|name| {
                                        name.starts_with("profile-") && name.ends_with(".conf")
                                    })
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                route_profiles.sort();
                match route_profiles.into_iter().next() {
                    Some(path) => path,
                    None => {
                        eprintln!("skip {release}: no golden profile");
                        continue;
                    }
                }
            };
        }
        expected += 1;
        let mut want = BTreeMap::new();
        parse_profile(&golden, &mut want);
        let Some(route) = primary_route(&want) else {
            eprintln!("skip {release}: bundled profile has no route");
            continue;
        };

        let (exit, stdout, stderr) = run(binary, image, &route, false);
        if stderr.contains("embedded BTF not found") {
            eprintln!(
                "skip {release}: no embedded BTF; no-BTF cross-family support is not claimed"
            );
            continue;
        }
        assert_eq!(exit, 0, "{release}: extractor failed\n{stderr}");
        /* Stage-5 contradiction fixture: the 6.6.66 vendor backport and the
         * 6.1.138 build both disagree with the 6.x template; the extractor
         * must name the losing member (`uid`) while emitting the BTF value. */
        if release.starts_with("6.6.66-") {
            assert!(
                stderr.contains("BTF cred.usage is 8"),
                "{release}: missing the BTF-usage warning\n{stderr}"
            );
            assert!(
                stderr.contains("BTF cred.uid is at +8"),
                "{release}: missing the BTF-uid warning\n{stderr}"
            );
        }
        if release.starts_with("6.1.138-") {
            /* The 6.1 usage/uid are 4/4 — the template agrees; its contradiction
             * is the security/cap offsets (120/40 vs the template's 128/48). */
            assert!(
                stderr.contains("BTF cred.security is +120"),
                "{release}: missing the BTF-security warning\n{stderr}"
            );
            assert!(
                stderr.contains("BTF cred cap_inheritable is +40"),
                "{release}: missing the BTF-caps warning\n{stderr}"
            );
        }
        let mut got = BTreeMap::new();
        parse_text(&stdout, &assets, &mut got);

        for (key, value) in &want {
            let block = key.split('.').next().unwrap_or("");
            if !matches!(
                block,
                "route" | "task_struct" | "cred" | "kernelsnitch" | "offset"
                    | "waiter_layout"
            ) {
                continue;
            }
            /* The SLUB stride is measured by the app's picker; the extractor
             * deliberately never emits it (stride-agnostic leak + native
             * default), so it is not an extractor-reproducible key. */
            if key == "kernelsnitch.mm_struct_sz" {
                continue;
            }
            /* A null in the bundled profile means "unused", not "must be
             * missing": the extractor may resolve the symbol anyway. */
            if value == "null" {
                continue;
            }
            assert_eq!(
                got.get(key),
                Some(value),
                "{release}: {key} differs\nimage: {}\n{stderr}",
                image.display()
            );
        }
        assert!(
            got.keys()
                .any(|key| key.starts_with(&format!("route.{route}."))),
            "{release}: forced route {route} is missing from the profile\n{stderr}"
        );

        /* The negative property: forcing the no-disassembly path must not
         * plant a constant from another family. A 5.10 `loggers+0x10` value
         * on a 6.1 profile is exactly the leak this test exists to catch. */
        let (exit, stdout, stderr) = run(binary, image, &route, true);
        assert_eq!(exit, 0, "{release}: --no-disasm failed\n{stderr}");
        let mut got = BTreeMap::new();
        parse_text(&stdout, &assets, &mut got);
        if let (Some(want_slot), Some(got_slot)) = (
            want.get("offset.slide_loggers_0_1"),
            got.get("offset.slide_loggers_0_1"),
        ) {
            assert_eq!(
                got_slot, want_slot,
                "{release}: --no-disasm emitted a foreign loggers anchor\n{stderr}"
            );
        }

        checked += 1;
        eprintln!("ok {release}: route {route}, {} bundled fields", want.len());
    }

    if expected == 0 {
        eprintln!("skipping: no cross-family image with a bundled profile");
        return;
    }
    assert_eq!(checked, expected, "some cross-family images were skipped");
}
