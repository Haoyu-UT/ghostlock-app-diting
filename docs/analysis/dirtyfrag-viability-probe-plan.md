# DirtyFrag execution-time viability probe and pipeline resolver — implementation plan (2026-11-10)

**Status:** proposed, for operator review. Parent design:
[`profile-pipeline-selection-plan.md`](profile-pipeline-selection-plan.md) (amended 2026-11-10: the
ordered pipeline list, resolved before W1) and
[`per-image-verdicts-and-dirtyfrag-bundling-plan.md`](per-image-verdicts-and-dirtyfrag-bundling-plan.md)
§2.4. This plan covers the probe, the ROM preflight and the resolver; the extractor's
`pipeline_order` (§7) is a prerequisite, not a separate design.

**Status 2026-11-10 — steps 1–5 done; steps 4–5 host-gated.** The positive-control spike passed
(`external/port/dirtyfrag-probe-spike-2026-11-10/`); the product probe (`libdfprobe.so` +
`DirtyfragProbe` + `ProbeCrypto`) is implemented and device-gated: build 717 passes with the
measured-DB record, and a seeded crash marker yields `Crashed`, no DB write, marker cleared. The
ROM preflight (`DirtyfragPlan.preflight`) is implemented and accepts the diting's libc++
(`page_remain=2520`, matching the stage-1 margin) with unit tests. The ordered pipeline list and
the resolver are implemented on the host: the extractor derives `pipeline_order` and writes the
profile's `pipeline = [ ... ]`, the app parses the list (legacy scalar/missing migrate), the cut
writes it, `PipelineResolver` walks the order before W1 with the preflight/probe/DB callbacks,
and the generation picker is retired. Remaining: the native resolved-scalar cross-check (step 6)
and the resolver's device gates (a diting run, a forced pre-W1 fallback, OnePlus/A16).

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
| measured DB | `MeasuredProfileStore` (`dirtyfrag.probe`, `dirtyfrag.probe_rom`, `dirtyfrag.probe_protocol`) | record a clear probe result; the resolver reads it for the viability step only (§5.1) |
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
3. **Positive ESP control (validated, §8).** A valid inner UDP segment (UDP header + a fixed
   16-byte sentinel, ESP padding/trailer with next-header UDP) AES-CBC encrypted under the same SA
   and sent to the encapsulation port; the decapsulated segment is received on a loopback
   `DatagramSocket`. A received sentinel proves the SA/policy/decrypt path, so the file test's
   failure is attributable to the send path or the ESP guard. Validated on the diting (spike
   evidence: `external/port/dirtyfrag-probe-spike-2026-11-10/`). The control runs first; an
   exception/timeout/mismatch is `SetupFailed`, never `PrimitiveFailed`.
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

Implemented as `DirtyfragPlan.preflight()` on the running ROM, sharing `build()`'s ELF/hook
analysis (the device gate: the diting's libc++ is `Feasible`, `page_remain=2520`):

- the sentry constructor exists in libc++'s dynamic symbols (the init/libbase import graph is the
  stage-1 static check, not re-parsed here);
- the cave fits: the remainder of the cave's **4 KiB page** — the exec segment's last page is the
  mapping the stub runs from — must hold the 420-byte blob. The RW segment's `.data.rel.ro` alias
  shares that page by design (COWed in live processes), so a shared page is not an overlap error;
  a cave at a page boundary has no executable page and is refused; the hook and blob must be
  inside the file; both branches must fit the ARM64 B range;
- DEFEX/verity/policy are recorded from what the app can see; the preflight does not claim more
  than the static read supports (the A16 second way is the only Samsung evidence).

`Feasible` or `Rejected(reasons)`; cached per boot id. The first draft rejected the diting's real
libc++ for "overlapping" the RW segment; the stage-1 margins (2520/2256, 640/1200) show the page
remainder is the intended rule.

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

### 5.1 Measured-DB record

A **clear** result is written to the on-device measured DB (`MeasuredProfileStore`), so the
device keeps the fact and a later run can use it instead of re-probing:

- **Clear** = `Pass` with the positive ESP control and the file control verified, or
  `PrimitiveFailed` with the positive control verified (the SA decrypts; both file blocks stay
  unchanged). `SetupFailed`, `Crashed` and `NotRun` are not written.
- **Keys** (schema v1 already stores multiple facts per kernel; no schema bump):
  - `dirtyfrag.probe` = `1` (pass) / `0` (primitive fail), source `dirtyfrag-probe`;
  - `dirtyfrag.probe_rom` = a 63-bit hash of `Build.FINGERPRINT` (the ROM the setup ran on);
  - `dirtyfrag.probe_protocol` = `1` (the probe protocol version).
  The evidence line of `dirtyfrag.probe` carries the human basis: `control=pass block=<old>-><new>
  want=<desired> rom=<fingerprint> protocol=1`; the UI shows source, evidence and `measured_at`.
- **Matching.** A `0` with a matching protocol is a kernel-scoped verdict: skip DirtyFrag on the
  same kernel without re-probing (the control proved the setup; the primitive is kernel-side). A
  `1` is reused only when the protocol and the ROM hash match; a different ROM re-probes (the
  setup may differ), though the kernel primitive is unchanged. Missing or stale keys → fresh
  probe. A new clear result overwrites the three keys.
- **Doctrine.** The measured DB stays a fact store, never a profile precedence layer. The probe
  fact is the one **run-path read** of the store, scoped to the resolver's viability step: it
  never changes a profile field, a route, or the pipeline list; it only feeds the entry that is
  already listed. An unreadable/newer-schema DB is not overwritten and not trusted — the resolver
  probes fresh. The `MeasuredProfileStore` class comment and `measured-db-plan.md` are amended
  with this scoped exception.
- **Write timing.** App-side, immediately after a clear result and before W1; a write failure is
  logged and does not block the run; a crash before the read-back writes nothing.

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

1. **The positive control — validated 2026-11-10.** The inner-UDP-sentinel control PASSed on the
   diting (5.10.236, Enforcing) together with the file test; the mechanism is fixed in §3 step 3
   and the evidence is `external/port/dirtyfrag-probe-spike-2026-11-10/`. Remaining: productize
   the fixed 16-byte sentinel and the control timeout.
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

1. ~~Spike the positive control on the diting~~ — **done 2026-11-10**: the inner UDP sentinel was
   received through the same SA and the file test PASSed. Evidence:
   `external/port/dirtyfrag-probe-spike-2026-11-10/`.
2. ~~`libdfprobe.so` + `DirtyfragProbe` (own file only); unit-test the IV vector and the result
   classification on the host; device: diting Pass~~ — **done 2026-11-10**: build 717 passes on
   the diting and records the DB facts; the crash marker yields `Crashed` with no write. Evidence:
   `external/port/dirtyfrag-probe-product-2026-11-10/`.
3. ~~`DirtyfragPreflight` from `DirtyfragPlan`; unit tests with synthetic ELF/plan cases; device:
   diting accepted, a synthetic cave-too-small case rejected~~ — **done 2026-11-10**: the
   page-remainder/boundary/file-end/branch rules are unit-tested and the diting's libc++ is
   `Feasible` (`page_remain=2520`). Evidence: the product session dir.
4. ~~`PipelineResolver` + run-store/UI; app tests for the matrix; remove the pipeline picker~~
   — **done (host) 2026-11-10**: the extractor emits `pipeline_order`, the app parses the list,
   `PipelineResolver` walks it with the preflight/probe/DB callbacks, and the picker is retired.
   The device matrix (a resolver run, the forced pre-W1 fallback) remains.
5. ~~Extractor `pipeline_order` + profile list + ship tool (can land in parallel; it gates the
   cut, not the probe)~~ — **done (host) 2026-11-10**: the extractor unit/store suites, the app
   tests and ship `--check` pass; the store supersets carry the order.
6. Native scalar cross-check; digest/golden.
7. Device gates: diting best-effort list resolves to DirtyFrag and the run completes; a forced
   setup failure falls to GhostLock **without W1** (device stays enforcing); a forced primitive
   failure (a patched kernel image, or a mocked probe in a debug build) is a fallback; the A16
   strict list runs DirtyFrag; the OnePlus best-effort list resolves to DirtyFrag.
8. Bundle audit and the release cut (the parent design's items).

### 9.1 Test matrix

**Host (no device):**

- **Crypto/IV:** AES-256-ECB decrypt of a known block (NIST vector) XOR desired; assert
  `AES-CBC-decrypt(key, that IV, old_block) == desired`. Pure JVM test; the JNI is not involved.
- **Classification:** (control pass, block changed) → `Pass`; (control pass, both blocks
  unchanged) → `PrimitiveFailed`; (control fail / setup exception) → `SetupFailed`; uncleared
  watchdog + new boot id → `Crashed`. None of the last three is written to the DB.
- **Measured DB:** record/load the three probe keys alongside the existing slabinfo fact (schema
  v1, multiple facts per kernel); evidence and `measured_at` round-trip; a DB without the probe
  keys loads; matching by kernel + protocol + ROM hash; a mismatched protocol/ROM is not reused;
  overwrite semantics; an unreadable/newer DB → no trust and no write; the slabinfo fact is
  untouched.
- **Resolver:** a fake DB/probe/preflight matrix — DB pass + matching ROM → no probe call; DB
  pass + different ROM → probe; DB fail → DirtyFrag skipped; `SetupFailed` → next entry /
  refusal; strict `["dirtyfrag"]`; KDP list refusal; no post-W1 fallback; run-store log.
- **App/UI:** profile list parse and validation; the picker is absent; the resolution and the
  measured fact appear with source/evidence; profile-core/app suites.

**Device (diting 5.10.236 unless stated):**

- **Pass path:** the probe returns `Pass`; the DB gets `dirtyfrag.probe=1`, `probe_rom`,
  `probe_protocol=1`; the Measurements screen shows the fact; a second run in the same boot/ROM
  resolves DirtyFrag from the DB (`probe=db`, no fresh probe) and the run completes.
- **Setup failure:** a debug hook forces `SetupFailed`; no DB write; the resolver falls to
  GhostLock **without W1** and `getenforce` stays `Enforcing`.
- **Primitive failure:** the 6.1 duchamp (copy send path) if the probe APK can be installed (the
  operator enables Install-via-USB); expect the control to pass and both file blocks unchanged →
  `PrimitiveFailed`, DB `0`, DirtyFrag skipped. If the device is unavailable, a debug-injected
  `PrimitiveFailed` covers the resolver matrix and the real copy-path probe stays a pending
  device gate.
- **Crash containment:** kill the app between the watchdog write and the read-back; on restart the
  marker + changed boot id → `Crashed`, no DB write, DirtyFrag refused; the device stays
  enforcing (the probe is pre-W1).
- **ROM preflight:** a synthetic cave-too-small plan → `RomRejected`; the resolver falls to
  GhostLock.
- **A16 strict list:** profile validation refuses `["dirtyfrag", "ghostlock"]` on KDP; the A16
  device run remains the reporter's/operator's gate.
- **OnePlus 6.6.66:** the probe passes and the best-effort list resolves DirtyFrag.
- **Gates:** every device run is recorded in the run store; the DB file and the Measurements
  screen are captured; the normal host suites pass.

### 9.2 Gates

Host gates: extractor unit/corpus, profile-core, app, native. Device gates as above; every
DirtyFrag run still requires the probe `Pass` (fresh or a matching DB record) and the preflight.

## 10. Non-goals

- Proving the ROM hook fires or the stage completes (the run is the test).
- Writing system files in the probe (the stage target is separate; the probe uses its own file).
- A probe on a device with no `IpSecService`/policy support (SetupFailed → fallback/refusal).
- The ordered-list extractor/app work beyond the prerequisites in §7 (covered by the parent
  design).
