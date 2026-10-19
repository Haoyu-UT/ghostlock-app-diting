//! The on-device derivation path, checked against the bundled profiles.
//!
//! The kernel images are gitignored, so this runs only when pointed at a
//! directory of them:
//!
//! ```text
//! GHOSTLOCK_IMAGE_DIR=../rom GHOSTLOCK_IOMAP=../iomap.txt \
//!     cargo test --test ondevice_profile -- --nocapture
//! ```
//!
//! For every `Image-5.10.*` found (recursively), the test runs the real
//! binary with `--format conf --anchor`, then compares the route, execution,
//! task_struct, cred, kernelsnitch and offset blocks against the bundled
//! profile of the same release. The per-image values (the ten offsets, the
//! three cred refs, the anchor) are what make this non-circular; the constants
//! are expected to match by construction.

use std::collections::{BTreeMap, BTreeSet};
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
        } else if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("Image-5.10."))
        {
            out.push(path);
        }
    }
}

/// Strip comments and split a profile into top-level blocks (by name) plus
/// top-level `key = value` lines (also under the empty name).
fn blocks(text: &str) -> BTreeMap<String, BTreeSet<String>> {
    let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut current: Option<String> = None;
    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if let Some(name) = &current {
            out.entry(name.clone())
                .or_default()
                .insert(line.to_string());
            if line == "}" {
                current = None;
            }
        } else if let Some(rest) = line.strip_suffix('{') {
            current = Some(rest.trim().to_string());
        } else if line == "}" {
            // unbalanced; ignore
        } else {
            out.entry(String::new())
                .or_default()
                .insert(line.to_string());
        }
    }
    out
}

fn release_of(text: &str) -> Option<String> {
    text.lines().find_map(|line| {
        line.trim()
            .strip_prefix("release = \"")
            .and_then(|rest| rest.strip_suffix('"'))
            .map(str::to_string)
    })
}

#[test]
fn local_images_reproduce_the_bundled_profiles() {
    let Some(image_dir) = std::env::var_os("GHOSTLOCK_IMAGE_DIR") else {
        eprintln!("skipping: GHOSTLOCK_IMAGE_DIR is not set");
        return;
    };
    let image_dir = PathBuf::from(image_dir);
    let iomap = std::env::var_os("GHOSTLOCK_IOMAP").unwrap_or_else(|| "/dev/null".into());
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let assets = manifest.join("../../app/src/main/assets/kernel_profiles");
    let binary = env!("CARGO_BIN_EXE_ghostlock-extract");

    let mut images = Vec::new();
    collect_images(&image_dir, &mut images);
    images.sort();
    assert!(
        !images.is_empty(),
        "no Image-5.10.* under {}",
        image_dir.display()
    );

    let mut checked = 0usize;
    for image in &images {
        let output = std::env::temp_dir().join(format!(
            "gl-ondevice-{}-{}.conf",
            std::process::id(),
            checked
        ));
        let status = Command::new(binary)
            .arg(image)
            .arg("--iomem")
            .arg(&iomap)
            .arg("--phys")
            .arg("0xa8000000")
            .arg("--format")
            .arg("conf")
            .arg("--anchor")
            .arg("--out")
            .arg(&output)
            .status()
            .expect("run extractor");
        assert!(status.success(), "extractor failed on {}", image.display());
        let derived = std::fs::read_to_string(&output).expect("read derived profile");
        let _ = std::fs::remove_file(&output);
        let release = release_of(&derived).expect("derived profile has a release");
        let bundled_path = assets.join(format!("{release}.conf"));
        if !bundled_path.is_file() {
            eprintln!("skip {release}: no bundled profile");
            continue;
        }
        let bundled = std::fs::read_to_string(&bundled_path).expect("read bundled profile");
        let want = blocks(&bundled);
        let got = blocks(&derived);
        for name in [
            "route",
            "execution",
            "task_struct",
            "cred",
            "kernelsnitch",
            "offset",
        ] {
            let want = want.get(name).cloned().unwrap_or_default();
            let got = got.get(name).cloned().unwrap_or_default();
            assert_eq!(
                want,
                got,
                "{release}: block {name:?} differs\nimage: {}",
                image.display()
            );
        }
        let anchor = derived
            .lines()
            .find(|line| line.trim_start().starts_with("lock_anchor_image"))
            .expect("anchor emitted");
        eprintln!("ok {release}: {}", anchor.trim());
        checked += 1;
    }
    assert!(checked > 0, "no image had a bundled profile");
}
