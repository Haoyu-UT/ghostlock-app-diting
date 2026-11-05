#!/usr/bin/env python3
"""Ship every golden profile from the test-kernels store into the app bundle.

Rule (CLAUDE.md): every store entry that has an option superset and at least
one feasible route is shipped as a bundled profile. Entries with
``corpus = btf-only | codegen | excluded``, entries without a superset, entries
without a feasible route, and an entry whose ``devices[]`` mixes null and
non-null physical pairs (a single HOCON map cannot carry both) are exempt.

The bundle asset is the CLI's default anchored cut (``--format conf --route
<best> --anchor --device <primary>``) rendered from the store Image with that
device's sidecars; the physical maps are then written from the superset's
``devices[]`` entries so every device in the set resolves. For the
sigreturn-only 5.10.43/5.10.81 kernels the route block is replaced with the
AArch32 compat select carrier (G1 QEMU on every store image, G4 device 10/10 on
the era 5.10.81); 5.10.101 stays sigreturn until it has a device gate. New
assets carry a SHIPPED GOLDEN header and are never overwritten by a later run.

Usage:
    tools/ship_golden_profiles.py --check    # report unbundled goldens, exit 1
    tools/ship_golden_profiles.py --apply    # render + index the missing ones

Paths default to this checkout; override with --store/--assets/--extract.
"""
import argparse
import glob
import json
import os
import re
import subprocess
import sys
import tempfile

APP = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOT = os.path.dirname(os.path.dirname(APP))  # <repo>/external/ghostlock-app -> <repo>
DEFAULT_STORE = os.path.join(ROOT, "external", "test-kernels")
DEFAULT_ASSETS = os.path.join(APP, "app", "src", "main", "assets", "kernel_profiles")
DEFAULT_EXTRACT = os.path.join(APP, "build", "extract", "release", "ghostlock-extract")

SKIP_CORPUS = {"btf-only", "codegen", "excluded"}
ROUTE_PRIORITY = ["select_stack", "sigreturn", "tcp_zerocopy", "multicast_waiter"]
# The sigreturn-only 5.10 kernels (5.10.43/81/101) also have the AArch32 compat
# select carrier (docs/analysis/compat-select-carrier-plan.md). For 5.10.43 and
# 5.10.81 the G1 QEMU gate (all six store images) and G4 (era 5.10.81 device,
# 10/10) back it, so a newly rendered profile uses it instead of sigreturn.
# 5.10.101 stays sigreturn: it is QEMU-gated only (no device gate).
COMPAT_PREFIXES = ("5.10.43-", "5.10.81-")
COMPAT_WAITER_HOME = 0x1B0
COMPAT_SELECT_DST_DEPTH = 0x1E0
# Same order as the Rust store harness (tests/common/mod.rs sidecar_args).
SIDECARS = [
    ("vendor_boot.img", "--vendor-boot"),
    ("xbl_config.img", "--xbl-config"),
    ("xbl_config.elf", "--xbl-config"),
    ("uefi.img", "--uefi"),
    ("dtbo.img", "--dtbo"),
]


class NotShippable(Exception):
    pass


def parse_meta(directory):
    fields = {}
    for line in open(os.path.join(directory, "meta.txt"), encoding="utf-8", errors="replace"):
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        fields.setdefault(key.strip(), value.strip())
    return fields


def split_devices(value):
    return [part.strip().strip('"') for part in value.split(",") if part.strip()]


def entry_devices(meta, directory):
    devices = split_devices(meta.get("devices", ""))
    if not devices:
        primary = meta.get("device", "").strip().strip('"')
        if primary:
            devices = [primary]
    if not devices:
        devices = sorted(
            os.path.basename(path)
            for path in glob.glob(os.path.join(directory, "devices", "*"))
            if os.path.isdir(path)
        )
    return devices


def entry_image(meta, directory):
    image = meta.get("image", "").strip().strip('"')
    if image:
        path = os.path.join(directory, image)
        if os.path.isfile(path):
            return path
    images = sorted(glob.glob(os.path.join(directory, "Image-*")))
    if len(images) == 1:
        return images[0]
    raise NotShippable("no Image-* file")


def read_options(directory):
    superset = None
    for path in sorted(glob.glob(os.path.join(directory, "options-*.json"))):
        superset = path
    if superset is None:
        raise NotShippable("no option superset")
    with open(superset, encoding="utf-8") as handle:
        return json.load(handle)


def sidecar_args(directory, device):
    sidecar_dir = os.path.join(directory, "devices", device)
    if not os.path.isdir(sidecar_dir):
        sidecar_dir = directory
    args = []
    for name, flag in SIDECARS:
        path = os.path.join(sidecar_dir, name)
        if os.path.isfile(path):
            args += [flag, path]
    return args


def choose_route(options):
    feasible = [
        route.get("route")
        for route in options.get("routes", [])
        if route.get("verdict") == "feasible"
    ]
    if not feasible:
        raise NotShippable("no feasible route")
    chosen = options.get("chosen")
    if chosen in feasible:
        return chosen
    for route in ROUTE_PRIORITY:
        if route in feasible:
            return route
    return feasible[0]


def phys_map_lines(options):
    """The two lines that make every device in the superset's devices[] resolve."""
    devices = options.get("devices") or []
    if not devices:
        return None
    loads = [
        (entry.get("device"), int(entry["kernel_phys_load"]))
        for entry in devices
        if entry.get("kernel_phys_load") is not None
    ]
    offsets = [
        (entry.get("device"), int(entry["kernel_phys_offset"]))
        for entry in devices
        if entry.get("kernel_phys_offset") is not None
    ]
    if loads and offsets and {name for name, _ in loads} != {name for name, _ in offsets}:
        raise NotShippable(
            "devices[] mixes null and non-null physical pairs; a map cannot carry "
            "both a null device and the others"
        )

    def render(items):
        if not items:
            return "null"
        return "{ " + ", ".join(f"{name} = {value}" for name, value in items) + " }"

    return (
        f"kernel_phys_load = {render(loads)}",
        f"kernel_phys_offset = {render(offsets)}",
    )


def compat_anchor(options):
    """The dump_skip.zeroes anchor triple, 8-byte aligned (the 5.10.43 fix)."""
    for candidate in options.get("candidates", []):
        name = candidate.get("name") or ""
        anchor = candidate.get("anchor")
        if anchor and "dump_skip" in name:
            image = int(anchor["image"])
            aligned = (image + 7) & ~7
            return aligned, int(anchor.get("bytes", 4096)), int(anchor.get("stride", 32))
    raise NotShippable("compat carrier: no dump_skip anchor candidate")


def replace_route_block(text, block):
    lines = text.splitlines()
    start = next(
        index for index, line in enumerate(lines) if line.strip() == "route {"
    )
    end = next(
        index for index in range(start + 1, len(lines)) if lines[index].rstrip() == "}"
    )
    lines[start:end + 1] = block.splitlines()
    return "\n".join(lines) + "\n"


def compat_route_block(image, anchor_bytes, anchor_stride):
    return "\n".join(
        [
            "route {",
            "  select_stack {",
            "    compact_waiter = 1",
            "    compat_carrier = 1",
            f"    waiter_home = {COMPAT_WAITER_HOME}",
            f"    select_dst_depth = {COMPAT_SELECT_DST_DEPTH}",
            f"    lock_anchor_image = {image}",
            f"    lock_anchor_bytes = {anchor_bytes}",
            f"    lock_anchor_stride = {anchor_stride}",
            "  }",
            "}",
        ]
    )


def replace_line(text, key, line):
    pattern = re.compile(rf"^{re.escape(key)}\s*=.*$", re.MULTILINE)
    if not pattern.search(text):
        raise RuntimeError(f"rendered profile has no {key} line")
    return pattern.sub(line, text, count=1)


def candidates(store):
    """Entries that are not excluded by corpus; no IO on the Image or superset yet."""
    found, exempt = [], []
    for meta_path in sorted(glob.glob(os.path.join(store, "*", "meta.txt"))):
        directory = os.path.dirname(meta_path)
        meta = parse_meta(directory)
        release = meta.get("release", "").strip().strip('"')
        if not release:
            continue
        corpus = meta.get("corpus", "")
        if corpus in SKIP_CORPUS:
            exempt.append((release, f"corpus = {corpus}"))
            continue
        found.append({"release": release, "directory": directory, "meta": meta})
    return found, exempt


def validate(entry):
    options = read_options(entry["directory"])
    devices = entry_devices(entry["meta"], entry["directory"])
    if not devices:
        raise NotShippable("no device sidecar set")
    compat = compat_anchor(options) if entry["release"].startswith(COMPAT_PREFIXES) else None
    entry.update(
        options=options,
        image=entry_image(entry["meta"], entry["directory"]),
        devices=devices,
        primary=devices[0],
        route=choose_route(options),
        maps=phys_map_lines(options),
        compat=compat,
    )
    return entry


def index_releases(assets):
    text = open(os.path.join(assets, "index.conf"), encoding="utf-8").read()
    return set(re.findall(r'release\s*=\s*"([^"]+)"', text))


def add_index_entries(text, releases):
    if not releases:
        return text
    lines = text.splitlines(keepends=True)
    start = next(
        index for index, line in enumerate(lines) if line.strip().startswith("profiles = [")
    )
    end = next(
        index for index in range(start + 1, len(lines)) if lines[index].strip() == "]"
    )
    marker = "  # GOLDEN: every test-kernels golden is shipped (tools/ship_golden_profiles.py).\n"
    block = []
    if not any(line.strip() == marker.strip() for line in lines):
        block.append(marker)
    block += [f'  {{ release = "{release}", file = "{release}.conf" }}\n' for release in releases]
    if lines[end - 1] and not lines[end - 1].endswith("\n"):
        lines[end - 1] += "\n"
    lines[end:end] = block
    return "".join(lines)


def render(extract, entry, out_path):
    command = [extract, entry["image"]]
    command += sidecar_args(entry["directory"], entry["primary"])
    command += [
        "--format", "conf",
        "--route", entry["route"],
        "--anchor",
        "--device", entry["primary"],
        "--out", out_path,
    ]
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(
            f"extractor exited {result.returncode}\n{result.stderr.strip()[-2000:]}"
        )
    if not os.path.isfile(out_path):
        raise RuntimeError("extractor wrote no profile")


def asset_text(entry, rendered):
    text = rendered
    if entry["maps"]:
        text = replace_line(text, "kernel_phys_load", entry["maps"][0])
        text = replace_line(text, "kernel_phys_offset", entry["maps"][1])
    if entry.get("compat"):
        image, anchor_bytes, anchor_stride = entry["compat"]
        text = replace_route_block(
            text, compat_route_block(image, anchor_bytes, anchor_stride)
        )
        route_label = (
            f"select_stack (compat carrier: waiter_home 0x{COMPAT_WAITER_HOME:x}, "
            f"select_dst_depth 0x{COMPAT_SELECT_DST_DEPTH:x}, anchor {image})"
        )
    else:
        route_label = entry["route"]
    header = (
        "# SHIPPED GOLDEN -- test-kernels golden (QEMU tier); generated, do not edit.\n"
        f"# store: {entry['release']}; route: {route_label}; "
        f"devices: {', '.join(entry['devices'])}\n"
        "# maintained by external/ghostlock-app/tools/ship_golden_profiles.py\n"
    )
    return header + text


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="report only, exit 1 on a missing golden")
    parser.add_argument("--apply", action="store_true", help="render and index the missing goldens")
    parser.add_argument("--store", default=DEFAULT_STORE)
    parser.add_argument("--assets", default=DEFAULT_ASSETS)
    parser.add_argument("--extract", default=DEFAULT_EXTRACT)
    parser.add_argument(
        "--only", action="append", default=[],
        help="limit to releases matching any given substring (debugging)",
    )
    args = parser.parse_args()
    if args.check and args.apply:
        parser.error("--check and --apply are mutually exclusive")
    apply = not args.check

    found, exempt = candidates(args.store)
    index = index_releases(args.assets)
    assets = {
        os.path.basename(path)[:-5]
        for path in glob.glob(os.path.join(args.assets, "*.conf"))
    }

    bundled = 0
    missing = []
    for entry in found:
        release = entry["release"]
        if args.only and not any(needle in release for needle in args.only):
            continue
        if release in index and release in assets:
            bundled += 1
            continue
        if release not in assets:
            try:
                validate(entry)
            except NotShippable as error:
                exempt.append((release, str(error)))
                continue
        entry["reasons"] = []
        if release not in index:
            entry["reasons"].append("not in index.conf")
        if release not in assets:
            entry["reasons"].append("no asset file")
        missing.append(entry)

    if args.check:
        for entry in missing:
            print(f"MISSING {entry['release']}: {', '.join(entry['reasons'])}")
        for name in sorted(index):
            if name not in assets:
                print(f"ORPHAN index entry {name}: no asset file")
        print(f"{bundled} bundled, {len(missing)} missing, {len(exempt)} exempt")
        return 1 if missing else 0

    if not missing:
        print(f"{bundled} bundled, 0 missing, {len(exempt)} exempt")
        return 0
    if not os.path.isfile(args.extract):
        parser.error(f"extractor not found: {args.extract} (build tools/extract_rs)")

    shipped = []
    index_only = []
    failures = []
    index_path = os.path.join(args.assets, "index.conf")
    for entry in missing:
        asset_path = os.path.join(args.assets, entry["release"] + ".conf")
        if not os.path.isfile(asset_path):
            with tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False) as handle:
                temp_path = handle.name
            try:
                render(args.extract, entry, temp_path)
                rendered = open(temp_path, encoding="utf-8").read()
            except Exception as error:  # noqa: BLE001 - report each entry, keep going
                failures.append((entry["release"], str(error)))
                continue
            finally:
                if os.path.exists(temp_path):
                    os.unlink(temp_path)
            with open(asset_path, "w", encoding="utf-8") as handle:
                handle.write(asset_text(entry, rendered))
            shipped.append(entry["release"])
        else:
            index_only.append(entry["release"])

    new_index = [release for release in sorted(shipped + index_only) if release not in index]
    if new_index:
        text = open(index_path, encoding="utf-8").read()
        text = add_index_entries(text, new_index)
        with open(index_path, "w", encoding="utf-8") as handle:
            handle.write(text)

    for release in shipped:
        print(f"shipped {release}")
    for release in index_only:
        print(f"indexed {release} (asset already present)")
    for release, reason in exempt:
        print(f"exempt  {release}: {reason}")
    for release, error in failures:
        print(f"FAILED  {release}: {error}", file=sys.stderr)
    print(
        f"shipped {len(shipped)}, indexed {len(index_only)}, exempt {len(exempt)}, "
        f"failed {len(failures)}, already bundled {bundled}"
    )
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
