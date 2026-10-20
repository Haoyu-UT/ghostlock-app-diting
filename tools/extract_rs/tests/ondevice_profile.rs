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
//! binary with `--format conf --anchor`, asserts the verdict JSON, and compares
//! the route, task_struct, cred, kernelsnitch and offset blocks against the
//! bundled profile of the same release (`execution` is app-supplied and
//! omitted). Images with two Feasible routes must exit 7 on the first pass;
//! the test then makes the bundled profile's choice explicitly with `--route`.

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

/// The route name of a rendered profile's `route { <name> { ... } }` block.
fn route_of(text: &str) -> Option<String> {
    let mut in_route = false;
    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line == "route {" {
            in_route = true;
        } else if in_route {
            if let Some(rest) = line.strip_suffix('{') {
                return Some(rest.trim().to_string());
            }
            if line == "}" {
                break;
            }
        }
    }
    None
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
    for (image_index, image) in images.iter().enumerate() {
        let output = std::env::temp_dir().join(format!(
            "gl-ondevice-{}-{}.conf",
            std::process::id(),
            image_index
        ));
        let feasible_out = std::env::temp_dir().join(format!(
            "gl-feasible-{}-{}.json",
            std::process::id(),
            image_index
        ));
        let run = |route: Option<&str>, output: &Path| {
            let mut command = Command::new(binary);
            command
                .arg(image)
                .arg("--iomem")
                .arg(&iomap)
                .arg("--phys")
                .arg("0xa8000000")
                .arg("--format")
                .arg("conf")
                .arg("--anchor")
                .arg("--feasible-out")
                .arg(&feasible_out)
                .arg("--out")
                .arg(output);
            if let Some(route) = route {
                command.arg("--route").arg(route);
            }
            command.status().expect("run extractor")
        };
        let status = run(None, &output);
        let exit = status.code();
        let _ = std::fs::remove_file(&output);
        let feasible_text = std::fs::read_to_string(&feasible_out)
            .expect("read feasible-out JSON after the first pass");
        let feasible: serde_json::Value =
            serde_json::from_str(&feasible_text).expect("parse feasible-out JSON");
        let routes = feasible["routes"].as_array().expect("routes array");
        let verdict_of = |route: &str| {
            routes
                .iter()
                .find(|entry| entry["route"] == route)
                .and_then(|entry| entry["verdict"].as_str())
                .unwrap_or("missing")
        };
        let feasible_routes: Vec<&str> = routes
            .iter()
            .filter(|entry| entry["verdict"] == "feasible")
            .filter_map(|entry| entry["route"].as_str())
            .collect();
        let chosen = feasible["chosen"].as_str();
        let release = image
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_prefix("Image-"))
            .expect("Image-<release> file name")
            .to_string();
        let patch = release
            .split('.')
            .nth(2)
            .and_then(|part| part.split('-').next())
            .and_then(|part| part.parse::<u32>().ok());
        match patch {
            Some(43) | Some(81) | Some(101) => {
                assert_eq!(feasible_routes, vec!["sigreturn"], "{release}");
                assert_eq!(verdict_of("select_stack"), "infeasible", "{release}");
                assert_eq!(verdict_of("multicast_waiter"), "infeasible", "{release}");
                assert_eq!(verdict_of("sigreturn"), "feasible", "{release}");
                assert_eq!(chosen, Some("sigreturn"), "{release}");
                assert_eq!(exit, Some(0), "{release}");
            }
            Some(136) | Some(177) | Some(198) | Some(209) | Some(226) | Some(236) => {
                assert_eq!(
                    feasible_routes,
                    vec!["select_stack", "sigreturn"],
                    "{release}"
                );
                assert_eq!(verdict_of("multicast_waiter"), "infeasible", "{release}");
                assert_eq!(chosen, None, "{release}: ambiguous pass must not choose");
                assert_eq!(exit, Some(7), "{release}: ambiguity must exit 7");
            }
            Some(246) => {
                assert_eq!(feasible_routes, vec!["multicast_waiter"], "{release}");
                assert_eq!(verdict_of("select_stack"), "infeasible", "{release}");
                assert_eq!(verdict_of("sigreturn"), "infeasible", "{release}");
                assert_eq!(chosen, Some("multicast_waiter"), "{release}");
                assert_eq!(exit, Some(0), "{release}");
            }
            _ => {}
        }

        // Every Feasible route gets its own expected profile. Prefer the
        // bundled device-verified asset when it is that route; otherwise use
        // the route-specific ground truth in the image directory, then the
        // primary profile.conf.
        let asset_path = assets.join(format!("{release}.conf"));
        let asset_text = asset_path
            .is_file()
            .then(|| std::fs::read_to_string(&asset_path).expect("read bundled profile"));
        let asset_route = asset_text.as_deref().and_then(route_of);
        assert!(!feasible_routes.is_empty(), "{release}: no feasible route");
        for route in &feasible_routes {
            let route_output = std::env::temp_dir().join(format!(
                "gl-route-{}-{}-{}.conf",
                std::process::id(),
                image_index,
                route
            ));
            let status = run(Some(route), &route_output);
            assert!(status.success(), "{release}: forced {route} failed");
            let derived = std::fs::read_to_string(&route_output).expect("read route profile");
            let _ = std::fs::remove_file(&route_output);
            assert_eq!(release_of(&derived).as_deref(), Some(release.as_str()));

            let route_file = image
                .parent()
                .expect("image parent")
                .join(format!("profile-{route}.conf"));
            let expected = if asset_route.as_deref() == Some(*route) {
                asset_text.clone().expect("asset text")
            } else if route_file.is_file() {
                std::fs::read_to_string(&route_file).expect("read route profile ground truth")
            } else {
                let primary = image.parent().expect("image parent").join("profile.conf");
                let text = std::fs::read_to_string(&primary).expect("read primary profile");
                assert_eq!(
                    route_of(&text).as_deref(),
                    Some(*route),
                    "{release}: primary profile is not the {route} route"
                );
                text
            };
            let want = blocks(&expected);
            let got = blocks(&derived);
            for name in [
                "route",
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
                    "{release}: {route} block {name:?} differs\nimage: {}",
                    image.display()
                );
            }
            assert!(
                !derived.contains("execution {"),
                "{release}: generated profile must not carry execution tuning; the app supplies it"
            );
            if *route != "multicast_waiter" {
                let anchor = derived
                    .lines()
                    .find(|line| line.trim_start().starts_with("lock_anchor_image"))
                    .expect("anchor emitted");
                eprintln!("ok {release} {route}: {}", anchor.trim());
            } else {
                eprintln!("ok {release} {route}");
            }
            checked += 1;
        }
        let _ = std::fs::remove_file(&feasible_out);
    }
    assert!(checked > 0, "no image had a bundled profile");
}
