//! Stage-5 fixture: the code-start survey is per image, not per release.
//!
//! ```text
//! GHOSTLOCK_SURVEY=../../external/port/cph2723-stock-kernel-2026-10-28/code-start-survey.txt \
//!     cargo test --test code_start_ondevice -- --nocapture
//! ```
//!
//! The survey disassembles each Image's own `request_standard_resources`; the
//! `adrp` constant is `_text` (0x0) or `_stext` (0x10000). The table is the
//! witness that a release predicate is wrong: 5.10 uses `_text`,
//! 5.15/6.1/6.6 and 6.12.23/30/38 use `_stext`, and 6.12.69 — the same device
//! as the 6.12.30 build one OS release earlier — goes back to `_text`.

use std::collections::BTreeMap;
use std::env;
use std::fs;

#[test]
fn code_start_is_per_image_not_per_release() {
    let Some(path) = env::var_os("GHOSTLOCK_SURVEY") else {
        eprintln!("skipping: GHOSTLOCK_SURVEY is not set");
        return;
    };
    let text = fs::read_to_string(&path).expect("read the survey");
    // The stock-OTA rows name the ROM and put the kernel release in the
    // annotation; carry the whole line so the 5.10 / 6.12.69 exception is
    // visible there too.
    let mut values: BTreeMap<String, (u64, bool)> = BTreeMap::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("Method") {
            continue;
        }
        let Some((image, rest)) = line.split_once('|') else {
            continue;
        };
        let image = image.trim();
        if image == "image" || image.starts_with("---") {
            continue;
        }
        let Some((_, constant)) = rest.split_once(',') else {
            continue;
        };
        let constant = constant.trim();
        let Some(hex) = constant.strip_prefix("0x") else {
            continue;
        };
        let end = hex
            .find(|c: char| !c.is_ascii_hexdigit())
            .unwrap_or(hex.len());
        let Ok(value) = u64::from_str_radix(&hex[..end], 16) else {
            continue;
        };
        let is_text = line.contains("5.10.") || line.contains("6.12.69");
        values.insert(image.to_string(), (value, is_text));
    }
    assert!(!values.is_empty(), "no survey rows parsed");
    assert!(values.len() >= 60, "only {} rows parsed", values.len());
    for (image, (value, is_text)) in &values {
        let expected = if *is_text { 0x0 } else { 0x10000 };
        assert_eq!(*value, expected, "{image}: code-start constant");
    }
    let six1230 = values
        .iter()
        .find(|(k, _)| k.starts_with("Image-6.12.30-"));
    let six1269 = values
        .iter()
        .find(|(k, _)| k.starts_with("Image-6.12.69-"));
    assert_eq!(six1230.map(|(_, (v, _))| *v), Some(0x10000));
    assert_eq!(six1269.map(|(_, (v, _))| *v), Some(0x0));
}
