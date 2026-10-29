//! Codegen-variant checks: the same 5.10 source and layout, built with
//! different compilers flags. These images are not phone kernels; they exist
//! to measure how far the no-BTF derivation reaches when the instruction
//! selection changes, and to assert that what it cannot derive is left null
//! or filled only by a fingerprinted template — never guessed.
//!
//! Runs only when GHOSTLOCK_IMAGE_DIR is set and the store carries
//! `Image-custom-*` builds with a `meta.txt` next to the image. The metadata
//! keys this test consumes:
//!
//! ```text
//! series = match|mismatch     IKCONFIG layout fingerprint against the measured series
//! template = yes|no           whether the series template may fill the rest
//! min_derived_task_fields = N coverage floor for the image's codegen
//! route = <route>             the route to render
//! ```
//!
//! Invariants checked for every image:
//! * every non-null `task_struct` value equals the measured series (soundness,
//!   independent of where the value came from);
//! * `template:` sources appear only when the fingerprint matches;
//! * a match+template image has no null field; a mismatch image has only
//!   derived or null fields;
//! * a failed `nf_logger` derivation is labelled `heuristic` in the log, and a
//!   successful one says `structure verified`;
//! * `--no-disasm` on a 5.10 image marks the fallback as a heuristic.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use ghostlock_extract::family;

fn collect_images(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_images(&path, out);
        } else if let Some(name) = path.file_name().and_then(|name| name.to_str()) {
            if name.starts_with("Image-custom-") {
                out.push(path);
            }
        }
    }
}

fn parse_meta(path: &Path) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let Ok(text) = std::fs::read_to_string(path) else {
        return out;
    };
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            out.insert(key.trim().to_string(), value.trim().to_string());
        }
    }
    out
}

fn first_word(value: &str) -> &str {
    value.split_whitespace().next().unwrap_or("")
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

fn field_sources(stderr: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for line in stderr.lines() {
        let Some(rest) = line.strip_prefix("info: field_source ") else {
            continue;
        };
        if let Some((name, source)) = rest.split_once('=') {
            out.insert(name.trim().to_string(), source.trim().to_string());
        }
    }
    out
}

fn task_block(profile: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut inside = false;
    for raw in profile.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line == "task_struct {" {
            inside = true;
            continue;
        }
        if inside {
            if line == "}" {
                break;
            }
            if let Some((key, value)) = line.split_once('=') {
                out.insert(key.trim().to_string(), value.trim().to_string());
            }
        }
    }
    out
}

#[test]
fn codegen_variants_derive_soundly_and_never_guess() {
    let Some(image_dir) = std::env::var_os("GHOSTLOCK_IMAGE_DIR") else {
        eprintln!("skipping: GHOSTLOCK_IMAGE_DIR is not set");
        return;
    };
    let binary = env!("CARGO_BIN_EXE_ghostlock-extract");
    let mut images = Vec::new();
    collect_images(Path::new(&image_dir), &mut images);
    images.sort();

    let mut checked = 0usize;
    for image in &images {
        let meta_path = image.parent().expect("image parent").join("meta.txt");
        let meta = parse_meta(&meta_path);
        let (Some(codegen), Some(series), Some(template), Some(min), Some(route)) = (
            meta.get("codegen"),
            meta.get("series"),
            meta.get("template"),
            meta.get("min_derived_task_fields"),
            meta.get("route"),
        ) else {
            eprintln!("skip {}: meta.txt has no codegen keys", image.display());
            continue;
        };
        let series = first_word(series);
        let template = first_word(template);
        let min: usize = min.parse().expect("min_derived_task_fields");
        let label = image
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("image");

        let (exit, stdout, stderr) = run(binary, image, route, false);
        assert_eq!(exit, 0, "{label}: extractor failed\n{stderr}");

        let sources = field_sources(&stderr);
        let derived = sources
            .iter()
            .filter(|(name, source)| name.starts_with("task_") && source.starts_with("derived:"))
            .count();
        assert!(
            derived >= min,
            "{label}: only {derived} derived task fields (floor {min})\n{stderr}"
        );

        for (name, _) in family::TASK_FIELDS {
            let source = sources
                .get(*name)
                .unwrap_or_else(|| panic!("{label}: no field_source line for {name}"));
            if source.starts_with("template:") {
                assert_eq!(
                    (series, template),
                    ("match", "yes"),
                    "{label}: template filled {name} without a fingerprint match"
                );
            }
            if series == "match" && template == "yes" {
                assert_ne!(
                    source, "null",
                    "{label}: {name} stayed null although the series matched"
                );
            }
            if series == "mismatch" {
                assert!(
                    !source.starts_with("template:"),
                    "{label}: {name} came from the template on a mismatch"
                );
            }
        }

        /* Soundness: whatever reached the profile must equal the measured
         * layout, no matter whether it was derived or templated. */
        let emitted = task_block(&stdout);
        for (name, value) in family::TASK_FIELDS {
            let key = name.trim_start_matches("task_");
            if let Some(got) = emitted.get(key) {
                if got != "null" {
                    assert_eq!(
                        *got,
                        value.to_string(),
                        "{label}: emitted {key} disagrees with the measured series"
                    );
                }
            }
        }

        /* The anchor must be either structurally derived or explicitly
         * labelled as a heuristic; an unlabelled fallback is a bug. */
        if stderr.contains("nf_logger derivation failed") {
            assert!(
                stderr.contains("heuristic"),
                "{label}: failed nf_logger derivation left an unlabelled fallback\n{stderr}"
            );
        } else {
            assert!(
                stderr.contains("structure verified"),
                "{label}: nf_logger success did not state the structure was verified\n{stderr}"
            );
        }

        /* Same rule on the no-disassembly path, where the derivation cannot
         * run at all and the 5.10 constant is the only source. */
        let (exit, _stdout, stderr) = run(binary, image, route, true);
        assert_eq!(exit, 0, "{label}: --no-disasm failed\n{stderr}");
        assert!(
            stderr.contains("heuristic"),
            "{label}: --no-disasm did not label the 5.10 anchor as a heuristic\n{stderr}"
        );

        checked += 1;
        eprintln!("ok {label}: codegen {codegen}, series {series}, template {template}, {derived} derived");
    }

    if checked == 0 {
        eprintln!("skipping: no Image-custom-* with codegen metadata");
        return;
    }
    assert!(checked > 0);
}
