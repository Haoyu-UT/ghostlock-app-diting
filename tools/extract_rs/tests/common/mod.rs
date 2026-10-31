//! Shared harness for the option-superset corpus.
//!
//! The store keeps one `options-<release>.json` per kernel; the tests run the
//! maximal extractor invocation (every sidecar, no route forced) and compare
//! the whole document. The corpus is meta-driven: every directory with a
//! `meta.txt` and an `Image-*` is a candidate, and `corpus = <kind>` takes it
//! out by policy (`excluded`, `btf-only`, `codegen`).

#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::Ordering;

#[derive(Clone, Debug)]
pub struct Meta {
    pub dir: PathBuf,
    pub release: String,
    pub corpus: Option<String>,
    pub phys: Option<u64>,
    pub image: Option<PathBuf>,
}

impl Meta {
    pub fn image(&self) -> &Path {
        self.image.as_deref().expect("corpus entry has an image")
    }
}

fn parse_phys(text: &str) -> Option<u64> {
    let text = text.trim();
    match text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
    {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => text.parse().ok(),
    }
}

/// Parse one entry directory's `meta.txt`. Returns `None` when it carries no
/// release line (not a kernel entry).
pub fn parse_meta(dir: &Path) -> Option<Meta> {
    let text = std::fs::read_to_string(dir.join("meta.txt")).ok()?;
    let mut release = None;
    let mut corpus = None;
    let mut phys = None;
    let mut image = None;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();
        match key.trim() {
            "release" => release = Some(value.trim_matches('"').to_string()),
            "corpus" => corpus = Some(value.to_string()),
            "phys" => phys = parse_phys(value),
            "image" => image = Some(dir.join(value)),
            _ => {}
        }
    }
    let release = release?;
    if image.as_ref().is_none_or(|path| !path.is_file()) {
        image = None;
        if let Ok(entries) = std::fs::read_dir(dir) {
            let mut candidates: Vec<PathBuf> = entries
                .flatten()
                .map(|entry| entry.path())
                .filter(|path| {
                    path.file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| name.starts_with("Image-"))
                })
                .collect();
            candidates.sort();
            if candidates.len() == 1 {
                image = candidates.pop();
            }
        }
    }
    Some(Meta {
        dir: dir.to_path_buf(),
        release,
        corpus,
        phys,
        image,
    })
}

/// Every image-bearing entry under `root`, minus the ones whose `meta.txt`
/// marks them out of the profile corpus. The marker is the single policy;
/// filename prefixes are not.
pub fn collect_all(root: &Path) -> Vec<Meta> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(root) else {
        return out;
    };
    let mut dirs: Vec<PathBuf> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect();
    dirs.sort();
    for dir in dirs {
        if !dir.join("meta.txt").is_file() {
            continue;
        }
        let Some(meta) = parse_meta(&dir) else {
            continue;
        };
        if let Some(kind) = &meta.corpus {
            eprintln!("skip (corpus {kind}): {}", dir.display());
            continue;
        }
        if meta.image.is_none() {
            eprintln!("skip (no image): {}", dir.display());
            continue;
        }
        out.push(meta);
    }
    out
}

/// The sidecars the entry carries, in the extractor's resolution order. The
/// extractor picks the one that carries the map and warns about the rest, so
/// passing every present file also exercises the fallback order.
pub fn sidecar_args(dir: &Path) -> Vec<std::ffi::OsString> {
    let mut args = Vec::new();
    for (file, flag) in [
        ("vendor_boot.img", "--vendor-boot"),
        ("xbl_config.img", "--xbl-config"),
        ("xbl_config.elf", "--xbl-config"),
        ("uefi.img", "--uefi"),
        ("dtbo.img", "--dtbo"),
    ] {
        let path = dir.join(file);
        if path.is_file() {
            args.push(flag.into());
            args.push(path.into_os_string());
        }
    }
    args
}

pub struct Run {
    pub exit: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub args: Vec<String>,
}

fn build_command(bin: &str, meta: &Meta) -> Command {
    let mut command = Command::new(bin);
    command.arg(meta.image());
    let sidecars = sidecar_args(&meta.dir);
    if sidecars.is_empty() {
        if let Some(phys) = meta.phys {
            command.arg("--phys").arg(format!("0x{phys:x}"));
        }
    } else {
        command.args(sidecars);
    }
    command
}

/// The store's single golden per kernel: the option superset document.
pub fn options_path(meta: &Meta) -> PathBuf {
    meta.dir.join(format!("options-{}.json", meta.release))
}

/// Run the maximal invocation: every sidecar, `--options-out <out>`, and a
/// temporary conf profile. The route is left unforced, so an ambiguous image
/// exits 7 after writing the document.
pub fn run_options(bin: &str, meta: &Meta, out: &Path) -> Run {
    let mut command = build_command(bin, meta);
    let profile = out.with_extension("conf.tmp");
    command
        .arg("--format")
        .arg("conf")
        .arg("--out")
        .arg(&profile)
        .arg("--options-out")
        .arg(out);
    let args: Vec<String> = command
        .get_args()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    let output = command.output().expect("run extractor");
    let _ = std::fs::remove_file(&profile);
    Run {
        exit: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        args,
    }
}

/// The CLI's default conf render for a route: `--anchor` with no operator
/// flags, which follows the same auto plan as the cut.
pub fn run_auto_conf(bin: &str, meta: &Meta, route: &str) -> Run {
    let mut command = build_command(bin, meta);
    command
        .arg("--format")
        .arg("conf")
        .arg("--route")
        .arg(route)
        .arg("--anchor");
    let args: Vec<String> = command
        .get_args()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    let output = command.output().expect("run extractor");
    Run {
        exit: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        args,
    }
}

/// The no-disassembly control for one route (negative test for a foreign
/// family constant leaking into another family's profile).
pub fn run_no_disasm(bin: &str, meta: &Meta, route: &str) -> Run {
    let mut command = build_command(bin, meta);
    command
        .arg("--format")
        .arg("conf")
        .arg("--route")
        .arg(route)
        .arg("--no-disasm");
    let args: Vec<String> = command
        .get_args()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    let output = command.output().expect("run extractor");
    Run {
        exit: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        args,
    }
}

/// Strip comments and split a profile into top-level blocks (by name).
pub fn blocks(text: &str) -> BTreeMap<String, BTreeSet<String>> {
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

/// Run `f` over `items` on a small worker pool. Each entry's extractor
/// invocations are independent subprocesses, so the corpus tests parallelize
/// for the same reason the generator does. Panics propagate when the scope
/// joins, after the remaining items have finished.
pub fn par_for_each<T: Sync, F: Fn(&T) + Sync>(items: &[T], workers: usize, f: F) {
    use std::sync::atomic::AtomicUsize;
    let next = AtomicUsize::new(0);
    let workers = workers.min(items.len()).max(1);
    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| loop {
                let index = next.fetch_add(1, Ordering::Relaxed);
                let Some(item) = items.get(index) else {
                    break;
                };
                f(item);
            });
        }
    });
}
