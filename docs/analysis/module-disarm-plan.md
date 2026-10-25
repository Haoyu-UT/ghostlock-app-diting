# vr.ko SELinux enforce-write block via the root script — plan (2026-10-25)

Status: **implemented on `experiment/vr-ko` (2026-10-25, user-authoritative tri-state); host gates
pass and the diting Auto no-op is verified.** L-level (handoff path plus a Native↔Kotlin
environment contract). No change to the route, payload, profile schema or wire format, and the
chain order stays as it is (W1 → W2 → W3 → handoff).

The file keeps `module-disarm-plan.md` as its historical name for citation stability; the feature
is **not** a module disarm. It blocks only the `/proc/vrp` 0/1 write that sets
`/sys/fs/selinux/enforce`.

Branch: carried on the combined vr.ko workstream branch **`experiment/vr-ko`** (Priority 1 of
`PORT-PLAN.md`), cut from **`document`** (`9c96125` at planning time) in its own worktree.
`port/diting-5.10` is the clean/upstream line and is **89 commits behind** the feature line
(measured 2026-10-25; `9c96125` is not an ancestor of it) — it is not the base for new work.
`BRANCH-POLICY.md` carries the same correction, dated.

## 1. Goal

On a 5.10.198-class device the only SELinux-relevant capability of `vr.ko` is `/proc/vrp`: a short
integer write sets `/sys/fs/selinux/enforce` (0/1), and a ≥ 64 KiB write installs a policy. The only
writer is the `vrp`-domain userspace daemon. Block that caller's path from the exploit's own rooted
child — bind `/dev/null` over the node, and STOP only the PIDs the mount cannot reach — so the
module cannot set SELinux back to enforcing while the handoff loads KernelSU.

**Stated narrowly:** this does **not** disarm, unload, patch or otherwise neutralize the module.
Its hooks, mounts, dumps and other checks continue to run; only the `/proc/vrp` 0/1 enforce write
is blocked.

## 2. Scope

- **In:** 5.10.198 (PD2314) as the Auto target; shell; the current chain order.
- **Out of Auto:** 5.10.246 (it creates `/proc/vrp` too, but writes < 64 KiB are `-EINVAL`; there
  is no enforce knob) and 6.6 (in-kernel tags; its node is a different interface). Under the
  user-authoritative rule a forced **On** still attempts the block there, with a warning and a
  `recommended=0` log; it is not device-gated by this plan.
- **Out wholly:** any claim of neutralizing the module; any kernel-side patching; any chain reorder
  (root-first is deferred).

## 3. Why this shape

- **User-authoritative, like the task-tag clear** (`vr-ko-countermeasure-plan.md` §0): the option
  is a tri-state UI control, and the 5.10.198 check is only what **Auto** recommends. The user's
  **On/Off** is final — a 5.10.246 or 6.6 device can be forced, with a warning, and a 198 device
  can be kept off.
- The block actions are AVC-checked (signal, mount, the module's own gate), so they only work once
  SELinux is permissive. W1 establishes that; the root script runs at the handoff, still permissive.
  No ordering change is required.
- The rooted worker is the only actor with `init_cred` (kernel SID); the app process is
  `untrusted_app` and cannot do it. The step therefore belongs in the root script, which already
  runs as that worker.
- Shell is sufficient: read `/proc/<pid>/attr/current`, `kill -STOP`, optionally bind-mount. No new
  native target, no route pollution, no profile field.
- A companion native `.so` was considered and rejected: it cannot reach a 6.x module's text with
  our primitives, and for the 198 it would only wrap the same shell operations.

## 4. Design

### 4.1 Option and transport

- New app preference `vrko_selinux_block`, tri-state **`auto` / `on` / `off`**, **default `auto`** —
  the same model as the task-tag clear (`vr-ko-countermeasure-plan.md` §0).
- The home entry **vr.ko anti-root countermeasures** opens the options screen; this option is the
  second tri-state row there, with its en/zh copy and one-line summary. There is no Advanced-section
  duplicate.
- **Auto** recommends the block only when `/proc/vrp` exists **and** `uname -r` starts with
  `5.10.198` — the only generation that builds the `0/1 → enforce` path. The 5.10.246 and 6.6
  generations therefore stay off under Auto; only an explicit **On** reaches them, and the row
  says it is untested.
- Direct entry passes `GHOSTLOCK_VRKO_SELINUX_BLOCK=auto|on|off` in the native environment,
  mirroring `GHOSTLOCK_VRKO_TAG_CLEAR`. `write_root_script()` embeds the requested mode into the
  generated script as `VRKO_SELINUX_BLOCK='...'` and the script resolves Auto itself (it is the
  process that sees the kernel and the node); the script is regenerated every run, so nothing
  depends on environment inheritance through `su`.
- The script's first line records
  `vr.ko selinux block: mode=... recommended=... effective=... kernel=... node=... reason=...`
  before any action. Every later line is a read-back for that path.

### 4.2 Script behaviour

`write_root_script()` (`src/core/attack/ops.cpp`) gains `vrko_selinux_block()` and one call, placed
immediately after the root-uid check and before the iomem cache and the policy fixup.

Resolution, in order (never a silent skip):

1. `mode=off` → log `reason=user-off`, return; no device change.
2. `/proc/vrp` absent → log `reason=node-absent`, return (nothing to block in any mode).
3. `mode=on` → `effective=1`, `reason=user-on`; when the kernel does not start with `5.10.198`,
   also log that the direction is untested there.
4. `mode=auto` → `recommended = uname -r starts with 5.10.198`; `effective=recommended`;
   `reason=auto-recommended` or `not-198-class`.

**Order: replace what the path resolves to first; signal only where that cannot reach.** Stopping a
vendor process is visible to any health check that watches it; a bind mount is not.

1. **Pre-log**, before any change: kernel, `stat -c %F /proc/vrp`, current `enforce`, every
   `u:r:vrp*` PID with its context, its mount namespace vs ours, and whether it holds an fd on the
   node.
2. **Primary — block new opens**: `mount --bind /dev/null /proc/vrp`. Read back `stat -c %F
   /proc/vrp` (must become `character special file`) and the `/proc/self/mountinfo` line. The
   module's handler is untouched; only the path's target is replaced.
3. **Effectiveness check**, per `vrp` PID: same mount namespace as ours (`/proc/<pid>/ns/mnt`), and
   no open fd on `/proc/vrp` (`/proc/<pid>/fd/*`). A PID the mount cannot reach — different
   namespace, or an already-open fd — is recorded and handled next.
4. **Fallback — `SIGSTOP`** exactly those uncovered PIDs (never KILL: a killed daemon may be
   restarted by its service manager; a stopped one stays stopped). Read back `State:` from
   `/proc/<pid>/status` (expect `T`) and re-scan `/proc/*/attr/current`.
5. **Post-log**: enforce, node type, mountinfo, each PID's state, and a re-scan; if a *running*
   `vrp` process appeared during the step, stop it once and log that too.

Never fatal; never unmount; never resume. The device stays modified until reboot, and the log says
so.

### 4.3 Script sketch (to be embedded as the generator text)

```sh
vrko_selinux_block() {
  mode="${VRKO_SELINUX_BLOCK:-auto}"
  kernel=$(uname -r)
  node=absent
  [ -e /proc/vrp ] && node=present
  rec=0
  case "$kernel" in 5.10.198*) rec=1 ;; esac
  if [ "$mode" = off ]; then
    echo "[*] vr.ko selinux block: mode=off recommended=$rec effective=0 kernel=$kernel node=$node reason=user-off" >>"$LOG"
    return 0
  fi
  if [ "$node" = absent ]; then
    echo "[*] vr.ko selinux block: mode=$mode recommended=$rec effective=0 kernel=$kernel node=absent reason=node-absent" >>"$LOG"
    return 0
  fi
  if [ "$mode" = on ]; then
    eff=1; reason=user-on
  else
    eff=$rec
    if [ "$rec" = 1 ]; then reason=auto-recommended; else reason=not-198-class; fi
  fi
  echo "[*] vr.ko selinux block: mode=$mode recommended=$rec effective=$eff kernel=$kernel node=$node reason=$reason" >>"$LOG"
  [ "$eff" = 1 ] || return 0

  myns=$(readlink /proc/self/ns/mnt 2>/dev/null)
  echo "[*] vr.ko selinux block: pre node=$(stat -c %F /proc/vrp 2>/dev/null) enforce=$(cat /sys/fs/selinux/enforce 2>/dev/null)" >>"$LOG"
  scan_vrp() {
    for f in /proc/[0-9]*/attr/current; do
      [ -r "$f" ] || continue
      ctx=$(cat "$f" 2>/dev/null) || continue
      case "$ctx" in u:r:vrp*)
        p=${f#/proc/}; p=${p%/attr/current}
        ns=$(readlink /proc/$p/ns/mnt 2>/dev/null)
        fd=$(readlink /proc/$p/fd/* 2>/dev/null | grep -c '/proc/vrp')
        echo "$p|$ctx|$ns|$fd"
      esac
    done
  }
  pre=$(scan_vrp)
  echo "[*] vr.ko selinux block: pre vrp=${pre:-none}" >>"$LOG"

  mount --bind /dev/null /proc/vrp 2>/dev/null; rc=$?
  echo "[*] vr.ko selinux block: bind rc=$rc node=$(stat -c %F /proc/vrp 2>/dev/null) mi=$(grep -c ' /proc/vrp ' /proc/self/mountinfo 2>/dev/null)" >>"$LOG"

  stopped=""
  for e in $pre; do
    p=${e%%|*}; ns=$(echo "$e" | cut -d'|' -f3); fd=$(echo "$e" | cut -d'|' -f4)
    if [ "$rc" -ne 0 ] || [ "$ns" != "$myns" ] || [ "$fd" -gt 0 ] || [ ! -c /proc/vrp ]; then
      kill -STOP "$p" 2>/dev/null && stopped="$stopped $p"
    fi
  done
  for p in $stopped; do
    echo "[*] vr.ko selinux block: stopped pid=$p $(grep -m1 '^State:' /proc/$p/status 2>/dev/null)" >>"$LOG"
  done
  post=$(scan_vrp)
  echo "[*] vr.ko selinux block: post node=$(stat -c %F /proc/vrp 2>/dev/null) enforce=$(cat /sys/fs/selinux/enforce 2>/dev/null) vrp=${post:-none}" >>"$LOG"
  return 0
}
vrko_selinux_block
```

## 5. Ordering and the window

The current order is kept. The block is the first step of the root script, i.e. after W2 and W3, so
the exposure is W1 → handoff. The daemon can still write `1` in that window; if it does before the
policy fixup, the fixup will fail (the kernel SID lacks `security load_policy` under enforcing) and
the KernelSU late-load will not happen. Placing the block immediately before the fixup minimises
that exposure. A root-first order would shorten it further but is out of scope here.

The tri-state changes *whether* the step runs, not *when* it runs: Auto turns it on only for the
198 class; a forced On on another 5.x kernel still runs after W1, in the same window.

## 6. Code map

| file | change |
|---|---|
| `src/core/attack/ops.cpp` (`write_root_script`) | the function text, the call, and the requested mode embedded as `VRKO_SELINUX_BLOCK`; the buffer was raised 12288 → 20480 (the generated script measured 9459 bytes) |
| `src/core/session/runtime_config.{h,cpp}` | `vrko_selinux_block` as the same three-value enum as the tag option (default auto), parsed from `GHOSTLOCK_VRKO_SELINUX_BLOCK`; the setup `vr.ko choices:` line is logged here |
| `app/.../domain/model/GhostlockModels.kt`, `domain/repository/GhostlockRepository.kt` | `VrKoMode` snapshot field + setter |
| `app/.../data/AndroidGhostlockRepository.kt` | `auto|on|off` preference, restore, snapshot, `GHOSTLOCK_VRKO_SELINUX_BLOCK` env (direct entry only) |
| `app/.../ui/{GhostlockUI,GhostlockViewModel,MainActivity}.kt`, `res/values*/strings.xml` | the compact home row + en/zh one-line text |
| `docs/analysis/module-disarm-plan.md` | this plan |

No profile/schema/digest/golden change. The Shizuku entry does not carry the variable and has no
root handoff; the setting applies to the direct entry only.

## 7. Gates

**Host**

- `make -C src ghostlock` zero warnings, `make -C src lint-tidy`, `make -C src native-host-tests`.
- Gradle unit tests (known `ProfileMigrationEquivalenceTest` fixture failure excepted) and
  `:app:assembleDebug`.
- One host test for the env parsing (`GHOSTLOCK_VRKO_SELINUX_BLOCK`) following the existing
  `runtime_config` tests; the script text itself is covered by the device gates.

**Device**

1. **Diting (5.10.236, no `/proc/vrp`)** — Auto (default) and Off: unchanged run; On: one
   `reason=node-absent` line, no other behaviour change, run completes (5/5 not required for a
   no-op stage; one fresh boot suffices).
2. **5.10.246 (reporter's)** — **Auto** (default): `reason=not-198-class`, `effective=0`, no
   perturbation. A forced **On** is the user's choice but is not device-gated here; do not run it
   in the gate series.
3. **5.10.198-class (when a device is available)** — **Auto** (default): `effective=1` and the log
   shows the `vrp` PIDs stopped (or a logged failure), `enforce` stays `0` after the script, and
   the chain completes to `KernelSU ready`; repeat on fresh boots; record in
   `external/github_error_reports/5.10.198-…/` and, if it changes the verdict, in `PORT-PLAN.md`.
   Also one **Off** run to prove the user override keeps it dark.

**Evidence:** the script's `$LOG` line, the run store, and the app log.

## 8. Risks and open questions

- **Watchdog:** a stopped vendor daemon may trip a vendor watchdog or health check. Unknown; Auto
  keeps non-198 devices untouched, and the user can force Off anywhere.
- **Mount reach:** the bind mount only affects processes in our mount namespace and only *new*
  opens. The step checks both (`/proc/<pid>/ns/mnt`, `/proc/<pid>/fd/*`) and falls back to SIGSTOP
  exactly for the PIDs the mount cannot reach.
- **Visibility:** a bind mount trips no process health check; a stopped process can. That is why
  blocking is primary and stopping is the fallback.
- **Restart:** a stopped daemon is not exited, so its service manager has nothing to restart; if a
  new `vrp` process appears anyway, the post-scan records it and the fallback stops it once.
- **SID matching:** the daemon context may not be exactly `u:r:vrp:s0`; the prefix match covers
  variants. If the scan finds nothing, the log says so and the handoff proceeds.
- **Residual window:** the W1 → script gap (see §5). If a 198 device shows the daemon winning that
  race, the answer is a race-free verify or a kernel-side primitive — not this plan.
- **Persistence:** the stopped daemon stays stopped until reboot; the log and the UI description
  must say so.
- **Option misuse:** Auto keeps the 246 and 6.6 generations off. A forced On there is the user's
  decision under the user-authoritative rule; the UI warns and the log records
  `reason=user-on recommended=0`.

## 9. Acceptance

- **Off** (any device): no observable change; one `reason=user-off` log line.
- **Auto**, node absent or kernel not 5.10.198: one `reason=node-absent` / `reason=not-198-class`
  line, no perturbation.
- **Auto**, 198-class: the `vrp` daemon is blocked/stopped (or the failure is logged), `enforce`
  remains `0` through the handoff, and the run completes with no new failure class.
- **On**, any node-bearing kernel: the step is attempted, the override and the recommendation are
  both logged; no silent skip is possible.
- Route, payload, profile schema and the 6.x tag countermeasure are untouched.

## 10. Decisions (settled 2026-10-25)

1. **Default Auto** under the user-authoritative rule: Auto recommends on only for
   `5.10.198` + `/proc/vrp`, off everywhere else; **On/Off are final**. (Replaces the earlier
   "default off" once the version check was demoted from a gate to a recommendation.)
2. **Block first** (bind mount); `SIGSTOP` the PIDs the mount cannot reach; never KILL.
3. Keep the block until reboot: no unmount, no resume.
4. Before/after read-backs on every path — node type, mountinfo, namespace/fd coverage, process
   state, `enforce` — the log must be enough to debug from alone.
5. The block method is not a user option: it is a coverage fallback (bind, then STOP exactly the
   PIDs the mount cannot reach), not a preference.

## 11. Implementation status (2026-10-25)

- Branch `experiment/vr-ko`, cut from `document` @ `9c96125`; the worktree changes are uncommitted
  for operator review.
- `write_root_script()` grew the function and raised its buffer 12288 → 20480; the generated
  script measured **9459 bytes** on the diting (the truncation guard stayed silent) and embeds
  `VRKO_SELINUX_BLOCK='auto'`.
- Host gates: `ghostlock` zero warnings, `lint-tidy`, `native-host-tests` (including the new
  `runtime_config_test`), Gradle 144 with the known fixture failure, `assembleDebug` 653, final APK
  md5 `0135dc7a…`, packaged native `1414f4f8…`.
- Device gate (diting 5.10.236, no `/proc/vrp`):
  `vr.ko selinux block: mode=auto recommended=0 effective=0 kernel=5.10.236-… node=absent
  reason=node-absent`; the script continued to the iomem cache and the policy fixup, and the chain
  completed. A second run with the spinner at **On** (pre-rename build) logged `mode=on
  recommended=0 effective=0 … node=absent reason=node-absent`: the override reaches the script and
  does not bypass the node check. The spinner was restored to Auto.
  `external/port/vr-ko-smoke-2026-10-25/`.
- Pending: the 198-class device (`effective=1`, the bind/coverage/STOP read-backs, `enforce`
  staying 0), the 246 Auto no-op (`reason=not-198-class`), and the forced-On directions.
