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
``devices[]`` entries so every device in the set resolves. The profile's
``pipeline`` line is the superset's derived ``pipeline_order`` (highest
precedence first), overridable per entry by ``pipeline = ...`` in ``meta.txt``.
A kernel whose
64-bit ``select_stack`` is infeasible (the superset's own verdict) is
``sigreturn``-only; for those the route block is replaced with the AArch32
compat select carrier (docs/analysis/compat-select-carrier-plan.md; G1 QEMU on
the six store images, G4 device 10/10 on the era 5.10.81). The carrier needs a
``dump_skip`` anchor candidate; when the superset has none, the profile keeps
``sigreturn``. New assets carry a SHIPPED GOLDEN header and are never
overwritten by a later run.

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
# The AArch32 compat select carrier's route block and geometry are the
# extractor's own now (analysis::apply_compat_select + report::
# conf_compat_route_geometry): a 5.10 pre-136 image whose 64-bit select is
# infeasible reports select_stack feasible with the measured family geometry,
# and the tool just renders the chosen route.
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


PIPELINES = ["ghostlock", "dirtyfrag"]


class PipelineChoiceRequired(Exception):
    """Both pipelines are feasible and the entry records no choice."""


def feasible_pipelines(options):
    return [
        entry.get("pipeline")
        for entry in options.get("pipelines", [])
        if entry.get("verdict") == "feasible"
        and entry.get("pipeline") in PIPELINES
    ]


def pipeline_reason(options, name):
    for entry in options.get("pipelines", []):
        if entry.get("pipeline") == name:
            return entry.get("reason", "")
    return ""


def choose_pipeline_order(options, meta):
    """The entry's curation override, or the superset's derived order.

    The superset carries the extractor's `pipeline_order` (highest precedence
    first, only statically feasible entries). `meta.txt` may override it with
    one name or a comma-separated order; every entry of the result must be
    feasible on this kernel.
    """
    feasible = feasible_pipelines(options)
    if not feasible:
        reasons = "; ".join(
            f"{entry.get('pipeline')}: {entry.get('reason', '')}"
            for entry in options.get("pipelines", [])
        )
        raise NotShippable(f"no feasible pipeline ({reasons})")
    raw = (meta.get("pipeline") or "").strip().strip('"').lower()
    order = [name.strip() for name in raw.split(",") if name.strip()]
    if not order:
        order = [
            str(name).strip().lower()
            for name in options.get("pipeline_order", [])
            if str(name).strip()
        ]
    if not order:
        # A superset written before the ordered list carried only verdicts;
        # use the extractor's default ranking.
        order = (
            ["dirtyfrag", "ghostlock"]
            if "dirtyfrag" in feasible and "ghostlock" in feasible
            else feasible[:1]
        )
    seen = set()
    for name in order:
        if name not in PIPELINES:
            raise PipelineChoiceRequired(f"unknown pipeline {name}")
        if name not in feasible:
            raise PipelineChoiceRequired(
                f"pipeline {name} is not feasible: {pipeline_reason(options, name)}"
            )
        if name in seen:
            raise PipelineChoiceRequired(f"duplicate pipeline {name}")
        seen.add(name)
    return order


def asset_pipeline_order(path):
    """The asset's `pipeline` order (list form, or a legacy scalar), or None."""
    try:
        text = open(path, encoding="utf-8").read()
    except OSError:
        return None
    match = re.search(r'(?m)^\s*pipeline\s*=\s*\[([^\]]*)\]', text)
    if match:
        names = re.findall(r'"([^"]+)"', match.group(1))
        return [name.strip().lower() for name in names] if names else None
    match = re.search(r'(?m)^\s*pipeline\s*=\s*"?([A-Za-z0-9_-]+)"?', text)
    return [match.group(1).strip().lower()] if match else None


def asset_has_stride(path):
    """Whether the rendered asset carries a `kernelsnitch.mm_struct_sz` value.

    Hand-finished assets are HOCON with `include "kernelsnitch-6x.conf"`, whose
    block carries the 1280 stride; follow one level of include so the check
    tests the effective document, not just the asset's own text.
    """
    try:
        text = open(path, encoding="utf-8").read()
    except OSError:
        return False
    if "mm_struct_sz" in text:
        return True
    base = os.path.dirname(path)
    for name in re.findall(r'(?m)^\s*include\s+"([^"]+)"', text):
        try:
            included = open(os.path.join(base, name), encoding="utf-8").read()
        except OSError:
            continue
        if "mm_struct_sz" in included:
            return True
    return False


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




def mm_struct_stride(directory, meta=None):
    """The measured /proc/slabinfo mm_struct objsize, or None.

    The extractor deliberately emits no stride (a generated profile should
    measure it, not seed it); the store's QEMU runtime dump is the usual
    measurement, and a device-only entry records it in meta.txt (`stride`).
    """
    for path in sorted(glob.glob(os.path.join(directory, "runtime-*.txt"))):
        for line in open(path, encoding="utf-8", errors="replace"):
            parts = line.split()
            if len(parts) >= 5 and parts[0] == "SLAB" and parts[1] == "mm_struct":
                try:
                    return int(parts[4])
                except ValueError:
                    return None
    if meta:
        value = (meta.get("stride") or "").strip()
        if value.isdigit():
            return int(value)
    return None


def set_mm_struct_stride(text, stride):
    """Write the measured slab stride into the kernelsnitch block."""
    line = (
        f"  # measured /proc/slabinfo mm_struct objsize {stride}.\n"
        f"  mm_struct_sz = {stride}\n"
    )
    existing = re.compile(r"^  mm_struct_sz\s*=\s*\d+\s*$", re.MULTILINE)
    if existing.search(text):
        return existing.sub(f"  mm_struct_sz = {stride}", text, count=1)
    block = re.search(r"^kernelsnitch\s*\{\s*\n", text, re.MULTILINE)
    if block:
        return text[: block.end()] + line + text[block.end():]
    return text + f"\nkernelsnitch {{\n{line}}}\n"


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
    entry.update(
        options=options,
        image=entry_image(entry["meta"], entry["directory"]),
        devices=devices,
        primary=devices[0],
        route=choose_route(options),
        maps=phys_map_lines(options),
        stride=mm_struct_stride(entry["directory"], entry["meta"]),
    )
    entry["feasible_pipelines"] = feasible_pipelines(options)
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
        "--pipeline-order", ",".join(entry["choice_pipeline_order"]),
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
    if entry.get("stride"):
        text = set_mm_struct_stride(text, entry["stride"])
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
    parser.add_argument("--check", action="store_true", help="report only, exit 1 on a missing or mismatched golden")
    parser.add_argument("--apply", action="store_true", help="render and index the missing goldens")
    parser.add_argument("--refresh", action="store_true", help="rewrite existing SHIPPED GOLDEN assets whose pipeline line or measured mm_struct_sz is missing/infeasible")
    parser.add_argument("--store", default=DEFAULT_STORE)
    parser.add_argument("--assets", default=DEFAULT_ASSETS)
    parser.add_argument("--extract", default=DEFAULT_EXTRACT)
    parser.add_argument(
        "--only", action="append", default=[],
        help="limit to releases matching any given substring (debugging)",
    )
    args = parser.parse_args()
    if args.check and (args.apply or args.refresh):
        parser.error("--check is mutually exclusive with --apply/--refresh")
    if args.apply and args.refresh:
        parser.error("--apply and --refresh are mutually exclusive")

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
        asset_path = os.path.join(args.assets, release + ".conf")
        has_asset = os.path.isfile(asset_path)
        try:
            validate(entry)
        except NotShippable as error:
            reason = str(error)
            # A hand-finished asset is the documented exception when the store
            # entry has no superset / no sidecar set / mixed physical pairs.
            # A stale asset on a kernel with no feasible route or pipeline is
            # a real content failure.
            hand_finished = has_asset and not any(
                phrase in reason
                for phrase in ("no feasible route", "no feasible pipeline")
            )
            if hand_finished:
                bundled += 1
            elif has_asset:
                entry["reasons"] = [f"asset present but entry is not shippable: {reason}"]
                missing.append(entry)
            else:
                exempt.append((release, reason))
            continue
        feasible = entry["feasible_pipelines"]
        if has_asset:
            if not feasible:
                entry["reasons"] = ["asset present but no feasible pipeline"]
                missing.append(entry)
                continue
            try:
                expected = choose_pipeline_order(entry["options"], entry["meta"])
            except PipelineChoiceRequired as error:
                entry["reasons"] = [str(error)]
                missing.append(entry)
                continue
            chosen = asset_pipeline_order(asset_path)
            if chosen is None:
                entry["reasons"] = [
                    f"asset has no pipeline line (expected {', '.join(expected)})"
                ]
                missing.append(entry)
                continue
            if chosen != expected:
                entry["reasons"] = [
                    f"asset pipeline {chosen} != derived order {expected}"
                ]
                missing.append(entry)
                continue
            if release not in index:
                entry["reasons"] = ["asset present but not in index.conf"]
                missing.append(entry)
                continue
            if entry.get("stride") and not asset_has_stride(asset_path):
                entry["reasons"] = [
                    f"asset has no mm_struct_sz (entry stride {entry['stride']}); "
                    "use --refresh"
                ]
                missing.append(entry)
                continue
            bundled += 1
            continue
        try:
            entry["choice_pipeline_order"] = choose_pipeline_order(
                entry["options"], entry["meta"]
            )
        except PipelineChoiceRequired as error:
            entry["reasons"] = [str(error)]
            missing.append(entry)
            continue
        except NotShippable as error:
            exempt.append((release, str(error)))
            continue
        entry["reasons"] = []
        if release not in index:
            entry["reasons"].append("not in index.conf")
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
    refreshed = []
    failures = []
    index_path = os.path.join(args.assets, "index.conf")
    for entry in missing:
        asset_path = os.path.join(args.assets, entry["release"] + ".conf")
        exists = os.path.isfile(asset_path)
        if exists and not args.refresh:
            failures.append((entry["release"], "asset exists; use --refresh to rewrite it"))
            continue
        if exists:
            first = open(asset_path, encoding="utf-8").readline()
            if not first.startswith("# SHIPPED GOLDEN"):
                failures.append((entry["release"], "asset is hand-finished; not overwritten"))
                continue
        if "choice_pipeline_order" not in entry:
            try:
                entry["choice_pipeline_order"] = choose_pipeline_order(
                    entry["options"], entry["meta"]
                )
            except (PipelineChoiceRequired, NotShippable) as error:
                failures.append((entry["release"], str(error)))
                continue
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
        if exists:
            refreshed.append(entry["release"])
        else:
            shipped.append(entry["release"])

    new_index = [release for release in sorted(shipped) if release not in index]
    if new_index:
        text = open(index_path, encoding="utf-8").read()
        text = add_index_entries(text, new_index)
        with open(index_path, "w", encoding="utf-8") as handle:
            handle.write(text)

    for release in shipped:
        print(f"shipped {release}")
    for release in refreshed:
        print(f"refreshed {release}")
    for release, reason in exempt:
        print(f"exempt  {release}: {reason}")
    for release, error in failures:
        print(f"FAILED  {release}: {error}", file=sys.stderr)
    print(
        f"shipped {len(shipped)}, refreshed {len(refreshed)}, exempt {len(exempt)}, "
        f"failed {len(failures)}, already bundled {bundled}"
    )
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
