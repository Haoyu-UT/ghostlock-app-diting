//! Masked-BTF truth diff: run the no-BTF 5.10 derivation on an image that
//! *does* carry BTF, and compare every derived value against the image's own
//! type information. This is the independent check the measured-series
//! comparison cannot provide: the series and the derivation could share a
//! mistake, BTF cannot.
//!
//! Runs only when GHOSTLOCK_IMAGE_DIR is set. Every `*.img` / `Image-*` under
//! it is loaded; those without embedded BTF or outside 5.10 are skipped.
//!
//! Assertions per image:
//! * every derived `task_struct` field equals the BTF offset;
//! * the measured series equals the BTF offset (a fingerprint match must mean
//!   an identical layout, and BTF is where that claim is tested);
//! * the credential caps offset/count/value close against the BTF fields
//!   `cap_inheritable`..`cap_ambient`.
//!
//! The credential reference offsets are printed, not asserted: BTF proves the
//! capability layout, while the reference pointers are image addresses whose
//! acceptance is a device-verified property of the series.

use std::path::{Path, PathBuf};

use ghostlock_extract::boot::BootImage;
use ghostlock_extract::btf::Btf;
use ghostlock_extract::derive::relative_symbols;
use ghostlock_extract::{family, kallsyms, kallsyms_finder, structs};

fn collect_images(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_images(&path, out);
        } else if let Some(name) = path.file_name().and_then(|name| name.to_str()) {
            if name.ends_with(".img") || name.starts_with("Image-") {
                out.push(path);
            }
        }
    }
}

#[test]
fn no_btf_derivation_equals_btf_truth_on_5_10() {
    let Some(image_dir) = std::env::var_os("GHOSTLOCK_IMAGE_DIR") else {
        eprintln!("skipping: GHOSTLOCK_IMAGE_DIR is not set");
        return;
    };
    let mut images = Vec::new();
    collect_images(Path::new(&image_dir), &mut images);
    images.sort();

    let mut checked = 0usize;
    for image in &images {
        let boot = match BootImage::load(image) {
            Ok(boot) => boot,
            Err(err) => {
                eprintln!("skip {}: {err}", image.display());
                continue;
            }
        };
        let Some((btf_offset, blob)) = boot.embedded_btf_at() else {
            continue;
        };
        let release = boot.release().unwrap_or_default();
        if !release.starts_with("5.10.") {
            continue;
        }
        let btf = match Btf::new(&blob) {
            Ok(btf) => btf,
            Err(err) => {
                eprintln!("skip {release}: BTF parse failed: {err}");
                continue;
            }
        };
        let symbols = kallsyms_finder::recover(&boot.kernel, Some((btf_offset, blob.len())))
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

        let mut derived_hits = 0usize;
        let mut series_checked = 0usize;
        let mut btf_missing = 0usize;
        for (name, series) in family::TASK_FIELDS.iter().copied() {
            let field = name.strip_prefix("task_").expect("task_ prefix");
            let Some(btf_value) = btf.field("task_struct", field) else {
                btf_missing += 1;
                continue;
            };
            assert_eq!(
                series, btf_value,
                "{release}: measured series says {name}={series} but the image's BTF says {btf_value}"
            );
            series_checked += 1;
            if let Some(got) = derived.values.get(name).copied() {
                assert_eq!(
                    got, btf_value,
                    "{release}: derived {name}={got} but the image's BTF says {btf_value}"
                );
                derived_hits += 1;
            }
        }

        let cred = structs::derive_cred_layout_5_10(&boot.kernel, init_cred_off, base)
            .expect("cred layout did not close");
        let btf_caps = btf
            .field("cred", "cap_inheritable")
            .expect("BTF cred.cap_inheritable");
        assert_eq!(
            cred.caps_offset, btf_caps,
            "{release}: caps offset disagrees with BTF"
        );
        assert_eq!(cred.caps_count, 5, "{release}: caps count");
        for (index, field) in [
            "cap_inheritable",
            "cap_permitted",
            "cap_effective",
            "cap_bset",
            "cap_ambient",
        ]
        .iter()
        .enumerate()
        {
            assert_eq!(
                btf.field("cred", field),
                Some(cred.caps_offset + 8 * index as u32),
                "{release}: {field} is not the expected consecutive cap slot"
            );
        }
        let refs: Vec<u32> = cred.refs.iter().map(|(offset, _)| *offset).collect();

        checked += 1;
        eprintln!(
            "ok {release}: {derived_hits}/{} derived, series {series_checked}/15 vs BTF, \
             BTF lacks {btf_missing}, caps 0x{:x}/{} value 0x{:x}, refs {refs:?}",
            derived.values.len(),
            cred.caps_offset,
            cred.caps_count,
            cred.caps_value
        );
    }

    if checked == 0 {
        eprintln!("skipping: no 5.10 image with embedded BTF");
        return;
    }
    assert!(checked > 0);
}
