# DirtyFrag execution-time viability probe and pipeline resolver — implementation plan (2026-11-10)

**Status:** proposed, for operator review. Parent design:
[`profile-pipeline-selection-plan.md`](profile-pipeline-selection-plan.md) (amended 2026-11-10: the
ordered pipeline list, resolved before W1) and
[`per-image-verdicts-and-dirtyfrag-bundling-plan.md`](per-image-verdicts-and-dirtyfrag-bundling-plan.md)
§2.4. This plan covers the probe, the ROM preflight and the resolver; the extractor's
`pipeline_order` (§7) is a prerequisite, not a separate design.

**Goal.** Before W1, decide whether DirtyFrag is viable on **this running ROM**, and feed the
ordered-list resolver. A pass is a licence to try DirtyFrag; a fail or an unverifiable result
falls to the next listed pipeline **before** the device becomes permissive. After W1 there is no
fallback — restore or reboot.

## 1. What the probe is, and what it is not

It is a **controlled execution of the page-cache primitive**: one 16-byte block of the app's own
file, spliced into a UDP packet under a transport-mode AES-CBC ESP transform, decrypted in place
by the kernel, read back. The evidence base is our stage-2 probe
(`external/port/dirtyfrag-stage2-2026-11-08/probe/`): the app's file PASSed on the diting with
SELinux Enforcing, no root, no daemon. DFRoot's `do_one_write_cbc()` is the same packet shape; its
`patch_helper()` read-back is **not** the model — it modifies a system file, checks one block, and
is fail-open when the verifying open fails.

It does **not** prove: that init's sentry constructor fires, that the stage completes, or that W1
will land. Those remain the ROM preflight + the run itself.

## 2. Components

| component | where | role |
|---|---|---|
| `DirtyfragProbe` | `app/.../data/DirtyfragProbe.kt` + `app/.../jni/dfprobe.c` (new `libdfprobe.so`) | the ESP send/read-back test; own file only |
| `DirtyfragPreflight` | `app/.../data/DirtyfragPreflight.kt`, reusing `DirtyfragPlan.kt` | the ROM-side structural check (hook import graph, cave fit, blob fit) |
| `PipelineResolver` | `app/.../data/PipelineResolver.kt` | read/validate the ordered list, walk it pre-W1, classify, cache, log |
| run store / UI | `GhostlockViewModel`, `RunStatusService`, strings | record the chosen entry and every rejection |
| native wire | `src/core/profile/` | parse the resolved `pipeline` scalar and cross-check the invocation |
| extractor | `tools/extract_rs` | `pipeline_order` (§7) |

The JNI code is a cleaned-up port of the stage-2 probe's native function (`probe.c`, 80 lines):
header `SPI(4)+Seq(4)+IV(16)`, `vmsplice(SPLICE_F_GIFT)`, `splice` 16 bytes from the file,
`splice` 40 bytes to the connected UDP socket. No `crash_dump64`, no system file, no vendor path.

## 3. Probe protocol

**File.** `filesDir/df-probe.bin`, 64 bytes, sentinel `0x40..0x7f`; block 0 is the target. The app
disposes/recreates it, so no restore is needed; a normal `FileOutputStream` write is the control
for the file/read path.

**Transform.** As the stage-2 probe: `IpSecManager` UDP encapsulation socket, loopback SPI,
random 32-byte AES key, transport-mode `CRYPT_AES_CBC` with `setIpv4Encapsulation`, no
authentication. The native receives `encapPort`, `senderPort`, `spi`, `aesKey`.

**Packet.** One block: `IV = AES_ECB_DEC(key, old_block) XOR desired_block`; the native sends
`SPI+Seq+IV+16` = 40 bytes. One `vmsplice`, one 16-byte file `splice`, one 40-byte socket
`splice`; all lengths exact. No retries inside the native call.

**Sequence and classification.**

1. Setup; any exception/`IpSecManager`/socket failure → `SetupFailed(reason)`. A setup failure is
   **not** "DirtyFrag broken".
2. File control: write the sentinel normally, read it back → proves the file/read path.
3. **Positive ESP control (spike, §8).** A file-free packet through the same SA whose decrypted
   payload the app observes. The candidate mechanisms: receive the decapsulated inner datagram on
   the encapsulation socket, or a second crafted packet with a sentinel carried in a pipe page and
   a userspace-visible result. If no reliable control can be built, the fallback is two distinct
   file blocks with different desired values; both must land. The control is required before the
   probe can distinguish "fixed/copy" from "transform not applied".
4. File test: ESP-write the desired block, poll the read-back for up to 1 s (20 × 50 ms); PASS
   iff the block is exactly the desired bytes.
5. Result: `Pass`, `PrimitiveFailed` (control passed, block unchanged), `SetupFailed(reason)`,
   `Crashed` (uncleared watchdog marker + changed boot id), `NotRun`.

**Safety envelope.**

- Own file only; one 16-byte block; one frag; valid transform parameters.
- A watchdog marker file is written before the probe and cleared after. On app start, an
  uncleared marker with a changed boot id means the probe (or the device) died; the result is
  `Crashed`, DirtyFrag is refused, and the reboot prompt path is used.
- No retry on `Crashed`; at most two attempts for `PrimitiveFailed` (page-cache race), none for
  `SetupFailed` beyond one transient retry.
- The probe runs **pre-W1**, in the app process; the resolver never falls back after W1.

## 4. ROM preflight

Reuse `DirtyfragPlan.build` on the running ROM (it already reads the libs, finds the sentry
constructor and computes the cave/branch layout):

- the hook target exists and is imported by init/libbase (the call path is present);
- the cave/blob fit (the plan's blob length, the tail-page fit, the zero-run fallback);
- the target file is readable and the block alignment is valid;
- record DEFEX/verity presence and any policy/service facts the plan can see; do not claim more
  than the static read supports (the A16 second way is the only Samsung evidence).

`RomFeasible` or `RomRejected(reasons)`. Cached per boot id; the ROM does not change mid-boot.

## 5. Resolver

Inputs: the profile's ordered list, the extractor verdicts (when the superset is present), the
ROM preflight, the probe, and the live state (SELinux, seccomp, manager).

```
for entry in list:
    validate(entry)                      # known name; statically feasible; KDP rules
    if entry == ghostlock:
        if static_feasible: return ghostlock
    if entry == dirtyfrag:
        if not static_feasible: reject
        if not rom_feasible: reject (reason)
        probe = cached_per_boot() or run_probe()
        if probe == Pass: return dirtyfrag
        reject (probe reason)
return Refused(all reasons)
```

- Every listed entry must be statically feasible; an infeasible fallback is a profile defect.
- On a KDP image the list must be `["dirtyfrag"]`; the resolver refuses GhostLock there.
- The chosen entry drives the native invocation: `dirtyfrag` → `--w1-only` then the stage;
  `ghostlock` → the full chain.
- The run store records `pipeline=<entry>` and `rejected=[dirtyfrag: <reason>, ...]`; the UI
  shows the same. A fallback is never silent.
- Probe/preflight results cache for the current boot id; a reboot (or a profile/ROM change)
  re-runs them.
- Stage failure after W1: the stub restores enforcing first when it fires; otherwise the app
  bounds the stage and prompts a reboot. The resolver is not re-entered.

## 6. Native / wire

The profile now carries the list; the app resolves it to one scalar and writes it into the native
document. Add `pipeline` to the binary profile's meta section, parse it into the profile model,
and have the session cross-check it against the invocation (`--w1-only`/`--dirtyfrag`/full) and
hard-error on a mismatch. Re-freeze the wire schema digest and the native-document golden; add
round-trip and mismatch tests. The list itself stays app-side.

## 7. Extractor prerequisites (ordered list)

- Derive `pipeline_order` from `pipelines[]`: both feasible → `["dirtyfrag", "ghostlock"]`; one →
  its one-element list; neither → refuse. Emit it in the superset and the cut; add
  `--pipeline-order` (validated) and stop requiring `--pipeline` in the normal path.
- The profile render writes `pipeline = [ ... ]`; the app's cut carries the order.
- `ship_golden_profiles.py` writes/validates the order; a `meta.txt` order is an optional
  curation override. Interim curation stays conservative until the resolver passes its device
  gates (device-verified entries only put DirtyFrag first).

## 8. Spikes and open questions

1. **The positive control.** The largest uncertainty: how to observe the SA's decryption without
   the file write (encap socket receive vs a pipe-sentinel packet). The probe is not shippable
   until the control works on the diting; without it, a FAIL cannot be attributed.
2. **JNI packaging.** A new `libdfprobe.so` (CMake/Make target, ABI, load path) versus adding the
   function to an existing native library. Keep the probe independent of the attack engine.
3. **Probe crash containment.** App-process watchdog + boot id; a kernel oops/reboot is a
   `Crashed` result and a refusal, never a retry.
4. **Preflight coverage.** How much of DEFEX/verity/policy the pre-W1 app can read; the A16 is the
   only Samsung data point.
5. **Caching.** Per boot id; invalidate on a profile/ROM change; a user-initiated re-probe.
6. **Disagreement policy.** Static feasible but probe primitive-failed → trust the probe; probe
   setup-failed → "cannot verify" (fall through a best-effort list, refuse a strict one).

## 9. Implementation order and gates

1. Spike the positive control on the diting (standalone probe APK, no product change).
2. `libdfprobe.so` + `DirtyfragProbe` (own file only); unit-test the IV vector and the result
   classification on the host; device: diting Pass.
3. `DirtyfragPreflight` from `DirtyfragPlan`; unit tests with synthetic ELF/plan cases; device:
   diting accepted, a synthetic cave-too-small case rejected.
4. `PipelineResolver` + run-store/UI; app tests for the matrix (both feasible with probe pass /
   primitive-fail / setup-fail; strict list; KDP; cache); remove the pipeline picker.
5. Extractor `pipeline_order` + profile list + ship tool (can land in parallel; it gates the cut,
   not the probe).
6. Native scalar cross-check; digest/golden.
7. Device gates: diting best-effort list resolves to DirtyFrag and the run completes; a forced
   setup failure falls to GhostLock **without W1** (device stays enforcing); a forced primitive
   failure (a patched kernel image, or a mocked probe in a debug build) is a fallback; the A16
   strict list runs DirtyFrag; the OnePlus best-effort list resolves to DirtyFrag.
8. Bundle audit and the release cut (the parent design's items).

Host gates: extractor unit/corpus, profile-core, app, native. Device gates as above; every
DirtyFrag run still requires the probe Pass and the preflight.

## 10. Non-goals

- Proving the ROM hook fires or the stage completes (the run is the test).
- Writing system files in the probe (the stage target is separate; the probe uses its own file).
- A probe on a device with no `IpSecService`/policy support (SetupFailed → fallback/refusal).
- The ordered-list extractor/app work beyond the prerequisites in §7 (covered by the parent
  design).
