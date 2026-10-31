//! Per-field derivation against the 5.10 test-kernel images.
//!
//! The diting line has no BTF, so the measured-series `task_struct` block and
//! the device-verified 236 cred block are the truth. This test proves the
//! anchors recover exactly those values on every stored 5.10 image; a missing
//! or different value is a stop, not an accepted candidate.
//!
//! ```text
//! GHOSTLOCK_IMAGE_DIR=../test-kernels cargo test --test structs_ondevice
//! ```

use std::path::{Path, PathBuf};

use ghostlock_extract::boot::BootImage;
use ghostlock_extract::derive::{derive_nf_logger_registration, relative_symbols};
use ghostlock_extract::family;
use ghostlock_extract::kallsyms;
use ghostlock_extract::kallsyms_finder;
use ghostlock_extract::structs;

/// One `key = value` line from a profile's `offset` block.
fn profile_offset(text: &str, key: &str) -> Option<u64> {
    text.lines().find_map(|line| {
        let line = line.split('#').next()?.trim();
        let (name, value) = line.split_once('=')?;
        if name.trim() != key {
            return None;
        }
        value.trim().parse().ok()
    })
}

/// The expected `offset` value: the superset's common profile when present,
/// else the legacy `profile.conf` (excluded/codegen directories keep theirs).
fn expected_offset(dir: &Path, release: &str, key: &str) -> Option<u64> {
    let superset = dir.join(format!("options-{release}.json"));
    if let Ok(text) = std::fs::read_to_string(&superset) {
        let value: serde_json::Value = serde_json::from_str(&text).ok()?;
        return value["profile"]["offset"][key]
            .as_str()
            .and_then(|value| value.parse().ok());
    }
    let text = std::fs::read_to_string(dir.join("profile.conf")).ok()?;
    profile_offset(&text, key)
}

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

#[test]
fn task_struct_and_cred_anchors_match_the_series() {
    let Some(image_dir) = std::env::var_os("GHOSTLOCK_IMAGE_DIR") else {
        eprintln!("skipping: GHOSTLOCK_IMAGE_DIR is not set");
        return;
    };
    let mut images = Vec::new();
    collect_images(Path::new(&image_dir), &mut images);
    images.sort();
    assert!(!images.is_empty(), "no Image-5.10.* under {image_dir:?}");

    /* The derivation is 5.10-specific; the fields shared by the measured
     * series are the truth on this line. */
    let expected: Vec<(&str, u32)> = family::TASK_FIELDS.to_vec();
    let mut checked = 0usize;
    for image in &images {
        let boot = BootImage::load(image).expect("load image");
        let btf = boot.embedded_btf_at();
        let btf_pair = btf.as_ref().map(|(offset, blob)| (*offset, blob.len()));
        let symbols = kallsyms_finder::recover(&boot.kernel, btf_pair)
            .expect("recover kallsyms")
            .symbols;
        let base = kallsyms::unique(&symbols, "_text")
            .or_else(|| kallsyms::unique(&symbols, "_head"))
            .expect("image base");
        let (relative, sorted) = relative_symbols(&symbols, base);
        let init_task_va = kallsyms::unique(&symbols, "init_task").expect("init_task");
        let init_cred_va = kallsyms::unique(&symbols, "init_cred").expect("init_cred");
        let root_group_va = kallsyms::unique(&symbols, "root_task_group").expect("root_task_group");
        let init_task_off = init_task_va - base;
        let init_cred_off = init_cred_va - base;

        let derived = structs::derive_task_struct_5_10(
            &boot.kernel,
            &relative,
            &sorted,
            init_task_off,
            init_task_va,
            init_cred_va,
            root_group_va,
        );
        let release = image
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_prefix("Image-"))
            .expect("Image-<release>")
            .to_string();
        for (name, value) in &expected {
            match derived.values.get(name).copied() {
                Some(got) => assert_eq!(
                    got, *value,
                    "{release}: {name} derivation disagrees with the measured series"
                ),
                /* `atomic_flags` has no stable single anchor; its absence is
                 * a miss, not a disagreement. Every other field, `seccomp`
                 * included, must close and match the series. */
                None if matches!(*name, "task_atomic_flags") => {}
                None => panic!("{release}: {name} did not close"),
            }
        }
        assert!(
            derived.values.len() >= 14,
            "{release}: only {} fields closed",
            derived.values.len()
        );

        let cred = structs::derive_cred_layout_5_10(&boot.kernel, init_cred_off, base)
            .unwrap_or_else(|| panic!("{release}: cred layout did not close"));
        let family_cred = family::cred_from_image(&boot.kernel, init_cred_off, base)
            .unwrap_or_else(|| panic!("{release}: family cred reference did not close"));
        assert_eq!(cred.caps_offset, 40, "{release}: caps offset");
        assert_eq!(cred.caps_count, 5, "{release}: caps count");
        assert_eq!(
            cred.caps_value,
            family::CRED_CAPS_VALUE,
            "{release}: caps value"
        );
        assert_eq!(
            cred.refs, family_cred.refs,
            "{release}: derived references differ from the device-verified offsets"
        );

        /* The nf_logger derivation must close without BTF and land on the
         * profile's own KASLR anchors. */
        let logger = derive_nf_logger_registration(&boot.kernel, &relative, &sorted, None)
            .unwrap_or_else(|err| panic!("{release}: nf_logger derivation failed: {err}"));
        assert_eq!(logger.nf_log_type_ulog, 1, "{release}: ULOG value");
        let release_dir = image.parent().expect("image parent");
        let want_loggers = expected_offset(release_dir, &release, "slide_loggers_0_1")
            .unwrap_or_else(|| panic!("{release}: no slide_loggers_0_1 in the superset/profile"));
        let want_logger = expected_offset(release_dir, &release, "slide_nfulnl_logger")
            .unwrap_or_else(|| panic!("{release}: no slide_nfulnl_logger in the superset/profile"));
        assert_eq!(
            logger.loggers_0_1, want_loggers,
            "{release}: derived loggers anchor disagrees with the profile"
        );
        assert_eq!(
            logger.nfulnl_logger, want_logger,
            "{release}: derived nfulnl_logger offset disagrees with the profile"
        );

        eprintln!(
            "ok {release}: {} fields, {} refs, caps 0x{:x}/{}",
            derived.values.len(),
            cred.refs.len(),
            cred.caps_offset,
            cred.caps_count
        );
        checked += 1;
    }
    assert!(checked > 0, "no image was checked");
}
