# The page-free W1 policycap repair and the reboot prompt (plan)

Level: **M** — the attack path is untouched; the change reorders the root script's
existing policy load (so no KernelSU-handoff step can precede it) and adds a post-run
safety surface in the app. No profile/wire change.

Status: **implemented and device-gated 2026-11-14** on the duchamp (6.1.138,
Android 16): the fresh-boot smoke and 3-run series landed the post-root load 4/4
(`policyload before=0 after=2`, `policy fixup rc=0` before the KernelSU handoff, the
fresh `security_load_policycaps()` batch with `always_check_network=0`), and the warm
(KernelSU-already-loaded) run reproduced the myron `EINVAL` 10/10 and showed the
dialog and the `0x676c6f65` notification. Evidence:
`external/port/reboot-prompt-2026-11-14/` (the private root repo).

## The defect

The page-free W1 writes a kernel address (the scratch alias) as the 8-byte value at
`selinux_state + 0`. Bytes 5 and 6 of every kernel address are `0xff`, and those bytes
are `policycap[3]` (`always_check_network`) and `policycap[4]` (`cgroup_seclabel`).
The W1 acceptance check only looks at the `initialized` byte, so the flip is silent.
With `always_check_network` on, SELinux runs the netif/peer/packet checks the policy has
no rules for; every packet is denied and the data path dies until the policy is
reloaded (measured on the myron, 6.12.23: `selinux_state+0` `0xffffff8049e5fd01`, 200
`avc: denied { ingress,egress } … tclass=netif` lines, ping 100 % loss).

A full policy load runs `security_load_policycaps()` (`security/selinux/ss/services.c`),
which re-derives `policycap[]` from the policy itself. The root script already loads the
live policy dump (the "policy fixup") after root; that load is the repair. Its position
was after the KMI parse and safe-mode block, and its failure exits before the
KernelSU handoff — so a failure in any of those steps could prevent the repair from
running where a later handoff would otherwise have run. On Android 16 ROMs the live
dump read (`cat /sys/fs/selinux/policy`) can fail `EINVAL` in a KernelSU `ksu` domain
(the duchamp's `su` shell reproduces it; the app's fresh-boot root script, whose domain
is the victim's, reads it and the load lands).

## The fix

1. **Root script order.** The policy load (the post-root fix) moves immediately after
   the debug setup and before `KVER`/`KMI`, safe mode and the KernelSU block. It now
   runs on every rooted child that reaches the script, independent of the handoff.
   The failure branch still restores enforcing and exits (the policy could not be
   repaired; the app prompt below is the recovery).
2. **App safety net.** When a run's log shows `page_free=1` and a W1 success marker
   (`SELinux permissive` / `SELinux already permissive`) but the post-root load did not
   land (`policy fixup rc=0` absent), and either the native exited non-zero or the
   fixup failed (`policy fixup rc=1`), the app:
   - appends a warning to the run log;
   - shows a `NOTICE` dialog (`reboot_recommended_title`/`_message`);
   - posts a separate, dismissible `Reboot recommended` notification (its own id, the
     run-status channel).
   A completed run whose fixup landed never prompts. The `policy fixup rc=1` arm also
   covers the myron shape: KernelSU was already loaded, so the native exited 0 while
   the caps stayed flipped.

## Why not repair in place

- The clean `selinux_state` word is a policy fact, not zero (the myron has caps
  [0,1,2,5] on). The W1 vehicle's value doubles as the rb-erase child pointer, so an
  address-valued store cannot carry it; the value-independent W1 write is the separate,
  larger plan of record.
- A policy reload needs a policy source. `/sys/fs/selinux/policy` works on the
  fresh-boot root script but fails `EINVAL` in a loaded-KernelSU domain; the
  `precompiled_sepolicy` the PORT-PLAN named is absent from both the duchamp (Android
  16) and the diting (Android 12) `/system` and `/vendor` trees. The prompt is the
  recovery for the cases the load cannot reach.

## Test

- Fresh-boot series on the duchamp (page-free compat select, external profile): every
  run must log `fixup: attempt N → policyload before=… after=… → policy fixup rc=0`
  **before** `late-load`/`KernelSU ready`; the debug dmesg carries a fresh
  `policy capability … always_check_network=0` set.
  → **Done 4/4** (smoke `20261114-042408`, series `…042627`, `…042758`, `…042927`);
  the dmesg batches at 75.317/75.674/72.746/70.289 s all read
  `always_check_network=0`, `cgroup_seclabel=0`.
- Warm run (KernelSU already loaded) reproduces the myron shape and must show the
  warning line, the dialog and the notification.
  → **Done** (`20261114-043548`): ten `cat /sys/fs/selinux/policy: Invalid argument`
  lines, native `code=0`, the `建议重启` dialog over the log and notification
  `0x676c6f65`; a reboot restored `Enforcing`. The first warm run (`…043100`) is the
  same failure without the prompt — its build's detector only looked for the delayed
  `policy fixup rc=1` line, which is written after the native exits.
- Unit: `RunSafetyTest` (successful fixup, failed native, failed fixup with exit 0,
  unreadable dump with the rc line lost, early error with a landed fixup,
  already-permissive, page path, pre-W1, error exit with landed fixup). **9/9.**
