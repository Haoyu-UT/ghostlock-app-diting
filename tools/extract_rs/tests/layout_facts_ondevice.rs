//! Env-gated corpus test for the stage-2 layout facts.
//!
//! The expectations are per family, not a universal law: they are the layouts
//! measured in the corpus BTF (5.15/6.1 compact with 4-byte usage; 6.6/6.12
//! non-compact with the 8-byte vendor backport). A vendor that diverges from
//! its family will fail here and should be recorded as a per-image sample.
//!
//! Run with:
//! `GHOSTLOCK_IMAGE_DIR=external/test-kernels cargo test --release \
//!  --manifest-path tools/extract_rs/Cargo.toml --test layout_facts_ondevice`

use ghostlock_extract::boot::BootImage;
use ghostlock_extract::btf::Btf;
use ghostlock_extract::fact::Source;
use ghostlock_extract::layout;
use std::path::{Path, PathBuf};

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
            .is_some_and(|name| name.starts_with("Image-"))
        {
            out.push(path);
        }
    }
}

fn major_minor(release: &str) -> (Option<u32>, Option<u32>) {
    let mut parts = release.split('.');
    (
        parts.next().and_then(|part| part.parse().ok()),
        parts.next().and_then(|part| part.parse().ok()),
    )
}

#[test]
fn layout_facts_match_the_family_btf() {
    let Some(dir) = std::env::var_os("GHOSTLOCK_IMAGE_DIR") else {
        eprintln!("skipping: GHOSTLOCK_IMAGE_DIR is not set");
        return;
    };
    let dir = PathBuf::from(dir);
    let mut images = Vec::new();
    collect_images(&dir, &mut images);
    images.sort();
    assert!(!images.is_empty(), "no Image-* under {}", dir.display());

    let mut with_btf = 0usize;
    for image in &images {
        let boot = BootImage::load(image).expect("load image");
        let release = boot.release().expect("kernel release");
        let btf_at = boot.embedded_btf_at();
        let btf = btf_at
            .as_ref()
            .map(|(_, blob)| Btf::new(blob).expect("parse BTF"));
        let facts = layout::derive(btf.as_ref(), &release);
        let (major, minor) = major_minor(&release);

        if btf.is_none() {
            assert_eq!(facts.rt_mutex_size.value, 32, "{release}: rt_mutex pitch");
            if major == Some(5) {
                assert!(facts.waiter_compact.value, "{release}: 5.x is compact");
                assert_eq!(
                    facts.waiter_compact.source,
                    Source::ReleaseTemplate,
                    "{release}: compact fallback label"
                );
                assert_eq!(
                    facts.cred_usage_size.value, "null",
                    "{release}: no BTF and no built-in cred"
                );
                assert_eq!(facts.cred_usage_size.source, Source::Unknown);
                if release.contains("-android12-9-") {
                    assert_eq!(facts.waiter_pi_tree.value, "0x18", "{release}");
                    assert_eq!(facts.waiter_task.value, "0x30", "{release}");
                    assert_eq!(facts.waiter_lock.value, "0x38", "{release}");
                    assert_eq!(facts.waiter_wake_state.value, "null", "{release}");
                }
            }
            continue;
        }

        with_btf += 1;
        assert_eq!(facts.rt_mutex_size.value, 32, "{release}: rt_mutex pitch");
        assert_eq!(facts.rt_mutex_size.source, Source::Btf, "{release}");

        match (major, minor) {
            (Some(5), Some(15)) | (Some(6), Some(1)) => {
                assert!(facts.waiter_compact.value, "{release}: compact waiter");
                assert_eq!(facts.cred_usage_size.value, "4", "{release}: usage width");
                assert_eq!(facts.cred_uid_offset.value, "4", "{release}: uid");
                assert_eq!(
                    facts.cred_security_offset.value, "120",
                    "{release}: security"
                );
                assert_eq!(facts.cred_caps_offset.value, "40", "{release}: caps");
                assert_eq!(facts.cred_copy_size.value, "128", "{release}: copy");
                assert_eq!(facts.waiter_pi_tree.value, "0x18", "{release}");
                assert_eq!(facts.waiter_task.value, "0x30", "{release}");
                assert_eq!(facts.waiter_lock.value, "0x38", "{release}");
                assert_eq!(facts.waiter_wake_state.value, "0x40", "{release}");
            }
            (Some(6), Some(6)) | (Some(6), Some(12)) => {
                assert!(!facts.waiter_compact.value, "{release}: non-compact waiter");
                assert_eq!(facts.cred_usage_size.value, "8", "{release}: usage width");
                assert_eq!(facts.cred_uid_offset.value, "8", "{release}: uid");
                assert_eq!(
                    facts.cred_security_offset.value, "128",
                    "{release}: security"
                );
                assert_eq!(facts.cred_caps_offset.value, "48", "{release}: caps");
                assert_eq!(facts.cred_copy_size.value, "136", "{release}: copy");
                assert_eq!(facts.waiter_pi_tree.value, "0x28", "{release}");
                assert_eq!(facts.waiter_task.value, "0x50", "{release}");
                assert_eq!(facts.waiter_lock.value, "0x58", "{release}");
                assert_eq!(facts.waiter_wake_state.value, "0x60", "{release}");
            }
            _ => {
                // 5.10 with BTF is not in the corpus; no family assertion.
            }
        }
    }
    assert!(
        with_btf > 0,
        "no BTF-bearing image under {}",
        dir.display()
    );
}
