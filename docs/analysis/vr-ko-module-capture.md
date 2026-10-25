# vr.ko diagnostic capture — design and scope (2026-10-23)

Status: implemented in the working tree; native build and `lint-tidy` pass. No profile-schema or
attack-path change.

## Why

The vivo 5.10.246 runs (2026-10-22) reached W2 for the first time and the `/proc/modules` probe
reported a `vr`-prefixed module. The fork's countermeasure clears two task words for that module;
its tag-B offset (`VR_TAG_B_OFF 0x2c`, aligned to `0x28`) was verified on a **6.1** vivo tree, and
on the 5.10.246 image `task+0x28` is `thread_info.scs_sp` (13 × `mrs x18, sp_el0; ldr x18,
[x18, #0x28]` in the Image; `CONFIG_SHADOW_CALL_STACK=y`). Zeroing it is a guaranteed fault the
next time the task runs, and the device has `CONFIG_PANIC_ON_OOPS=y`.

The countermeasure is therefore unsafe on 5.10 until its real tag layout is known, and the layout
can only be read from the module binary. The module is a loadable vendor module (not in the GKI
Image; the boot ramdisk we have is the generic one and carries no modules), loaded from the vendor
partitions.

The probe also could not answer "is it really loaded?": the old code printed the same
`vr.ko loaded; clearing tags` line when `/proc/modules` was **unreadable** (it assumes loaded), and
it discarded the module name. This change fixes both.

## What it does

In the direct entry (`libghostlock.so` launched by the app as the app uid), at the W2 stage:

1. `/proc/modules` is read once. The matched module's name (first token, kept to `[A-Za-z0-9_-]`)
   is captured, and the probe logs `vr.ko probe: /proc/modules readable=%d name=%s`, so "matched"
   and "unreadable, assumed" are distinguishable in the export.
2. Before the tag-clear writes (so a panic caused by them cannot lose the copy), the module file is
   searched in fixed directories — `/vendor/lib/modules`, `/vendor_dlkm/lib/modules`,
   `/lib/modules`, `/system/lib/modules` — with the suffixes `.ko`, `.ko.xz`, `.ko.gz`, `.ko.zst`
   and both the underscore and hyphen spellings of the name.
3. The first regular file ≤ 16 MiB is copied to `<run-dir>/vr-module<source-suffix>` (mode 0600,
   fsynced), and `<run-dir>/vr-module.txt` records `module`, `probe_readable`, `probe_needed`,
   `source`, `bytes`, `result` (`ok` / `not-found` / `rejected-size-or-type` / `copy-failed` /
   `open-dst-failed` / `no-name`).
4. Every failure is logged and recorded, never fatal.

The read happens after W1 has made SELinux permissive, so the only gate on a vendor module is its
DAC mode (usually 0644); no root is needed. The app's run folder is the exporter's unit:
`RunLogStore.zip` already includes **every** file in it except `meta`, so no export change is
needed.

Plumbing: the app passes the run folder to the native as `GHOSTLOCK_RUN_DIR` (direct entry only —
the Shizuku user service runs as uid 2000 and cannot write the app's private directory). The native
reads it into `RuntimeConfig.run_dir`; empty disables the capture.

## What it does not do

- It does not change the tag-clear writes or the `VR_TAG_B_OFF` macro; the profile-controlled
  countermeasure option (`execution.vr_ko.{mode,tag_b_offset}`) is a separate, L-level change
  (wire schema on both sides) planned next.
- It does not capture the module when the run never reaches W2 (W1 must have succeeded), or on the
  Shizuku entry.

## Verification

- `make -C src ghostlock` — zero warnings.
- `make -C src lint-tidy` — exit 0.
- `:app:assembleDebug` — succeeds; the packaged `libghostlock.so` contains
  `vr.ko probe: /proc/modules readable=%d name=%s`, `vr-module.txt` and `GHOSTLOCK_RUN_DIR`.
- The next vivo run that reaches W2 should export `vr-module.ko*` and `vr-module.txt` in the run
  zip (or record `not-found` with the tried directories). Disassemble the module's task-tag stores
  to fill the future `tag_b_offset`.
