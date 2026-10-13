# Run logs: app-private store, rotating, exported on demand

Status: implemented, awaiting a device try. Decisions here are deliberately
provisional — they are meant to be changed after the first run on the phone.

## The problem, restated

Two facts, both measured:

1. The export folder is shared storage reached through MediaStore/FUSE. Written
   bytes sit in that mount's page cache until write-back, and a failed run on
   this ROM ends with the device going down hard. A report arrived in exactly
   that shape: three files, correct sizes, zero non-zero bytes. The artifact
   that would have explained the failure was destroyed by the failure.
2. Every run created `Download/ghostlock-debug-log/<stamp>/` and nothing ever
   removed them — 182 folders on the development device, ~40 KB each (~770 KB
   when the root path's dmesg dump lands). Clutter, not a space problem, but
   the user has to look at it.

## Design

* **One store, app-private.** `files/runs/<stamp>/` holds `log`,
  `profile.conf`, `profile.bin`, the root script's kernel dumps, and `meta`
  (`entry=`, `state=`, `started=`). That directory is on `/data`, not FUSE, and
  the app owns its descriptors, so fsync means what it says.
* **Nothing is written to shared storage at run time.** No folder accumulates in
  Downloads. The `debug_export_location` preference and the MediaStore write
  path go away with it.
* **Rotation, not accumulation.** The newest `Keep = 10` runs survive; older
  ones are deleted when a run starts. Constants live at the top of
  `RunLogStore` so the count is one edit.
* **Export on demand.** The main screen's *Export log* action opens a picker
  over the retained runs (newest first, with entry, state and size); choosing one
  opens the system save dialog (`ACTION_CREATE_DOCUMENT`, `application/zip`) and
  the app streams a zip `<stamp>.zip` containing that run's files under a
  `<stamp>/` folder — the same shape as the report that prompted this.
* **Interrupted runs are named as such.** A run writes `state=running` when it
  opens and `completed`/`failed` when it ends. Any run still marked `running`
  at the next app start was killed with the device: it is marked `interrupted`,
  sorted first in the picker, and its zip is named accordingly. This is the fact
  we had to *infer* from file sizes when the report arrived; from now on the log
  says it.

## What this costs

* The kernel dumps move into the run directory, so `--dump-kernel-log` now
  points at app storage. Root writing there is **not verified** — it is the same
  fallback the SELinux policy working copy used. If SELinux denies it, the dump
  fails loudly in the run log and everything else still works. First thing to
  check on the device try.
* Our own harness reads `/sdcard/Download/ghostlock-debug-log`. It has to move to
  `adb exec-out run-as com.ghostlock.app …` (verified: the released APKs are
  `android:debuggable=true`, so this works without root — which matters because
  a device that has just crashed is unrooted until the exploit runs).

## Not in this change

* No upload, no share sheet beyond the save dialog. A report is a file the user
  chooses to send.
* No per-run deletion in the UI beyond *Clear logs*.
