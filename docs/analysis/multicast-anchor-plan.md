# Multicast anchor (A-mechanism) — plan

**Status: APPROVED, implemented, and device-validated on the custom diting kernel (2026-10-22);
only the final merge remains.** The operator approved the 246 anchor
`lock_anchor_image = 0x2ec7bd8`, `lock_anchor_bytes = 0x400`, `lock_anchor_stride = 0x20` (the
`dump_skip.zeroes` safe prefix, profile data only). L-level change (attack-critical path and
profile/wire format); the code commits follow §7. Branch `experiment/multicast-anchor`, cut from
`document` @ `32b9ca8`.

**Progress 2026-10-21.** Steps 1–2 are implemented on `experiment/multicast-anchor` (this commit): the
profile/schema anchor trio and the anchored multicast stamp. Host gates: `ghostlock` zero
warnings, `lint-tidy` exit 0, profile/app tests pass (the documented pre-existing
`ProfileMigrationEquivalenceTest` failure remains), `assembleDebug` succeeds; the 5.15 multicast
builtin's `native-doc-golden.sha256` row was re-frozen because the wire digest covers the route's
declared keys (no profile value changed). `native-host-tests` still stops on the pre-existing
`document`-branch ARM64 `yield` asm on x86_64; the other 26 targets pass. `cmp_disasm` against the
step-1 snapshot: `do_kernel5_fake_lock_route` 174→375 (the anchored branch), `waiter_thread` +2
argument-materialization instructions with identical call targets, layout-shift-only annotations;
the known two MISSING multicast symbols reproduce in the baseline-vs-itself control.

**Device result 2026-10-22.** The diting custom-kernel gate passed end to end: the `ksun-only`
`-Os` Image passed the KMI/vermagic and frame gates; a RAM-only boot reached Android with every
vendor module; the derived custom profile ran the anchored multicast; the smoke run logged nine
clean anchored attempts and `exploit complete`; and the 6/arm A/B on the flashed Image gave
**anchored A 4/4 conditional on the shared page-prep (4/6 overall) vs page-based B 0/6** (five
`route clean=1/1` but W1 write unverified; one reboot/hang in the route). The 246 **profile's**
gate is still the reporter's vivo (W1 A/B with the `enforce` read) and the profile stays
non-device-gated; **the branch's only remaining step is the final merge** — commit steps 1–2,
re-run the tree gates on the committed tree, merge into `port/diting-5.10`, then `document`, and
cut the next release (the operator's call).

**Cross-device status (2026-10-21).** The 6.1 POCO cannot test the anchored multicast: strip home
0x1e8 vs copy depth 0x338, `waiter_off 0x150`, short by 0x88, and no safe anchor was found
(`dump_skip.zeroes` absent; the 6.1 anchor scan's reference counts are unreliable on that image).
Its shipped tcp/select routes are unaffected. The diting 236 can be made feasible with a custom
ACK build: `CONFIG_CC_OPTIMIZE_FOR_SIZE=y` with LTO/CFI kept measures `waiter_off 0xa8` on a full
Image — the eleven-word stamp fits with 8 bytes spare; `CONFIG_COMPAT=n` and `LTO_NONE` are
device-breaking. **Gates (1)–(3) were run on 2026-10-21 and pass:** the `ksun-only` @ `759dee338`
Image built with `-Os` and `BUILD_NUMBER=14313284` has a byte-identical banner/UTS_RELEASE/
vermagic to the stock kernel, 7,252 exports with 0 missing/extra and 0 CRC/class/namespace
differences (from both `vmlinux.symvers` and the Image's own `__ksymtab`; the in-tree KMI list
union is the same 7,252), and unchanged frames — `waiter_off 0xa8` with the 8-byte margin.
(4) passed on 2026-10-21: a RAM-only `fastboot boot` of the built Image (stock ramdisk, no
partition written) reached `boot_completed=1` in 9 s; 417/418 loadable modules, the only
difference being `kernelsu` (now built-in); no symbol/CRC/CFI failures; Wi-Fi connected; KSU `su`
root. (5) the custom-Image profile is derived (`profile-multicast-ksun-osize.conf`: ten
offsets from the 5x extractor, stock control exact; anchor `dump_skip.zeroes` +0x222b590 /
4096 / 32; route `waiter_off=0xa8`). **The smoke run passed on 2026-10-22:** imported over the
hand-picked builtin, nine anchored attempts all `clean=1/1`, `multicast route status=0`,
`exploit complete` at T+26.4 s, run store `state=completed`. **The A/B pilot (6/arm on the custom
kernel) then ran:** anchored A 4/4 conditional on the shared page-prep (4/6 overall; the two
failures are `prepare_kernel_page` rejecting all sprayed pages) vs page-based B 0/6 (five runs
`route clean=1/1` but W1's write did not verify; one reboot/hang in the route). Route-level
Fisher p ≈ 0.005. The anchored route is device-backed; the page-prep check is the remaining
whole-chain limiter. The A-mechanism branch is committed in this change; the final merge remains.

**Question.** Can the `multicast_waiter` route's write vehicle stop depending on the *contents* of
the reclaimed payload page by moving the fake `rt_mutex` to a zeroed `.bss` anchor, keeping the tree
node in the stack copy, and pointing the waiter's `task` at `init_task`?

**Decision summary**

- Build the A-mechanism into the existing `multicast_waiter` route. The carrier
  (`setsockopt(MCAST_BLOCK_SOURCE)`), its copy geometry, and the consumer handshake stay unchanged.
- The write becomes **content-page-independent** for W1's `lock` and `task`. W1's tree stamp still
  uses a page-*address*-derived scratch value (`page_base + 0x100`); the address is known from the
  leak and is a different question from the measured 3/160 content delivery. W2's fake fops/cred
  copy remains page-based and is out of scope for this build.
- **The 5.10.246 anchor gate is NOT passed yet, and the leading candidate changed.** The ranked
  scan's `rsc_seq_file` was **rejected after a QEMU provenance check**: it sits inside the active
  vendor **rsc** driver's dense `.bss` block (8 bytes after `rsc_slowpath_spinlock`, among
  `rsc_seq_*`/`rsc_slowpath_*` state), and the driver's probe/init runs in the guest (`rsc probe
  done`, `RSC rsc driver init done!`). A boot-time zero of 16 bytes is not evidence for a live
  driver's `seq_file`. The leading alternative is the **`dump_skip.zeroes` safe prefix** (image
  +0x2ec7bd8, safe length 0x440; the first 0x400 bytes have no references and read zero in the
  guest after driver init). It is the same symbol the diting uses, but on 246 its overall verdict
  is `unsafe` (a store at +0x440); the operator approved the safe prefix on 2026-10-21 (image
  0x2ec7bd8, bytes 0x400, stride 0x20). A full candidate list (177 candidates: 72 safe / 31
  needs-review / 74 unsafe) found **no better candidate** — the large `safe` rows outside the rsc
  range are live subsystem statics, and the needs-review rows have live reads. The prefix is the
  only path; the 246 profile carries it as data.
- **No device can gate this today** except the reporter's 246 vivo. The diting's multicast is
  geometrically infeasible (0x48 short on 5.10.236), and the app cannot run in QEMU. The 246 profile
  stays non-device-gated; nothing in this plan changes that.

## 1. Why this mechanism

The 5.10.246 device fails at W1 (SELinux): the route reports `status=0 clean=1/1 calls=1 success=1`
but the write does not verify. The port's 2026-10-21 verification established:

- every geometry value the profile uses is exact (static and in-guest runtime);
- `kernel_phys_load` is `0xA8000000` (firmware memory map; the run profiles already carried it);
- `SLUB_MIRROR` is an opt-in, per-cache **object-level** allocation redirect, not a page-lifetime
  hook, and all caches read 0 at boot.

What remains is the route's delivery: `multicast_waiter_route.cpp` stamps only the waiter's `task`
and `lock`, both read from `heap.current` — the reclaimed payload page. The write is the PI walk's
tree erase through the fabricated `rt_mutex`/waiter in that page. If the page's contents are not
ours, the walk either sees `owner == 0` and returns cleanly (the clean-but-unwritten signature) or
spins.

The diting's history is the precedent. Its option 1 (reclaim the freed slab page via the skb frag
path) was closed by measurement: the frag path drew from our free set **3/160** times. Its option 2
replaced the *lock* with a zeroed `.bss` anchor (`dump_skip.zeroes`, image +0x2a3a590, 0x1000
bytes, stride 0x20, 128 slots/boot) and kept the tree node on the stack; that is the shipped select
route. One correction to the shorthand: the diting's shipped select route is **lock-anchored, not
page-free** — its `task` word still comes from `payload_base` (`util.cpp:452`,
`select_stack_route.cpp:530`). The A-mechanism adds the second half: `task = slide_init_task()`,
the page-free choice the TCP route already makes (`tcp_zerocopy_route.cpp:265-266`).

## 2. What the design can rely on

| fact | value | how it was established |
|---|---|---|
| 246 futex chain | `0xe0+0xc0+0x1b0 = 0x350`; waiter `futex_wait_requeue_pi` sp+0x20 → strip home **0x330** | static disassembly + QEMU runtime |
| 246 multicast copy | `ip_setsockopt` greqs sp+0x20 → **Σ0x360**, L=0x108/264; `waiter_off = 0x30` | static + QEMU runtime |
| 246 waiter fields | `task +0x30`, `lock +0x38`, `prio +0x40` (5.10 `int prio`), `deadline +0x48` | static; the 5.10 shape |
| 246 profile | `waiter_off=48`, `buffer_size=264`, `task_offset=48`, `lock_offset=56` | the device-ran profile |
| anchor API | `route/lock_anchor.{h,cpp}` — `acquire_lock_word(image, bytes, stride, attempt, &slot)`; boot-scoped slot serial; `0` = fail the route | shipped select/sigreturn code |
| anchor grid (diting control) | `dump_skip.zeroes` image +0x2a3a590, 0x1000 bytes, stride 0x20, 128 slots; direct map boot-invariant | device-verified option 2 |
| 246 named anchor | `dump_skip.zeroes` image +0x2ec7bd8, 0x440 bytes — **unsafe**; omitted from the hand profile | 5x extractor verdict |

The anchor's `attempt` argument is **log-only**: `acquire_lock_word()` delegates the rotation to
`allocate_slot()`, which is the boot-scoped serial, so the multicast route does not need the
backend's retry number for correctness. It should still log a monotonic value.

## 3. The stamp: what changes

The current encoder writes two words:

```
encode_multicast_waiter(buffer, waiter_offset, task_offset, lock_offset,
                        heap.current.fake_task, heap.current.fake_lock)
```

The A-mechanism writes the full eleven-word waiter through the shared encoder
(`encode_waiter_words(buffer, waiter_offset, words)`, `payload_builder.h`), with
`waiter_words(stamp_layout, task, lock, prio)`:

| word | value | page content needed? |
|---|---|---|
| `tree_pc` | `waiter_tree_stamp(stamp_layout).pc` | no — see below |
| `tree_right`, `tree_left` | stamp triple | no |
| `pi_pc`, `pi_right`, `pi_left` | 0 (pi side parks) | no |
| `task` | `ghostlock::profile::slide_init_task()` (direct-map alias) | **no** (replaces `heap.current.fake_task`) |
| `lock` | `anchor::acquire_lock_word(...)` slot; `0` fails the route | **no** (replaces `heap.current.fake_lock`) |
| `prio` | `kernel::waiter_prio_word(kernel::FAKE_WAITER_PRIO, compact_waiter_has_wake_state())` | no |
| `deadline`, `ww_ctx` | 0 | no |

Fit: `waiter_offset 0x30 + kWaiterBytes 0x58 = 0x88` ≤ `buffer_size 0x108`. The encoder must
refuse an undersized buffer; add a unit test for exactly that.

### The page-address distinction

`payload_write_layout()` gives W1 (`WriteMode::Zero`, `preserve_child=true`; the backend calls
`retry_write_stage(..., mode=1, leaf=0)`) a tree stamp of
`{pc = page_base + 0x100, right = 0, left = target}`. The erase stores `pc` at `left` (the target)
and uses the page-derived pointer as its collateral scratch. **The page's contents are not read**;
the page's *address* is known from the leak, and `payload_write_layout_accepts_page()` already gates
the value's byte 2 (`selinux_state.initialized`).

So the A-mechanism removes the page-*content* dependence for the lock and task, not every use of
the page address. A fully page-free W1 value (an anchor-derived scratch with the byte-2 constraint)
is a possible follow-up, not part of this build: the anchor slot's 0x20 stride does not give a
scratch region separate from the lock object, and the current `accepts_page` gate already covers
the address case.

## 4. Design

### 4.1 Route

`multicast_waiter_route.cpp`:

1. Read `multicast_layout()`; require `buffer_size`, `waiter_offset`, `task_offset`, `lock_offset`
   as today, plus the anchor trio when the A-mechanism is enabled.
2. If the anchor trio is present:
   - acquire the lock word (a `0` return is a route failure, never a neighbour slot);
   - build `WaiterWords` with `slide_init_task()`, the anchor lock, the family-gated prio, and the
     tree stamp from the request layout;
   - `encode_waiter_words` at `waiter_offset`;
   - log the anchor image offset, slot, direct-map address, and the stamped triple.
   If the anchor is absent, keep the current two-word stamp and `heap.current.fake_lock/fake_task`
   (compatibility path; the profile decides).
3. Keep the family word at offset 8, the socket, the `setsockopt`, and the consumer handshake
   unchanged. The route's `status=0` remains a syscall-success signal only; the W1 verdict is the
   backend's `verify`.

The route is called once per attempt; W1 is forced to `w1_attempts = 1` for multicast
(`cve_2026_43499_backend.cpp:497-500`), so the anchor must land on the first try for W1.

### 4.2 Profile and schema

Follow the sigreturn precedent: the anchor trio is duplicated in the route's own section because
the decoder never merges across routes (`kRouteSigreturn`'s comment). Add, all optional and with
absence preserving today's behavior:

- `profile-core/.../route/MulticastConfig.kt`: `lockAnchorImage/Bytes/Stride`, `entries()`,
  `apply()`, `SchemaKeys`, `from()`.
- `src/core/profile/model.h`: `MulticastWaiterLayout` gains the trio; `multicast_layout()` fills it
  from the shared geometry fields (the same `select_lock_anchor_*` storage the sigreturn route
  already reuses — no new geometry members).
- `src/core/profile/binary.cpp`: add the three `OPT` rows to `kRouteMulticast`.
- `docs/kernel_profiles/PROFILE_SCHEMA.md` and `_ZH`: document the new keys and the
  "absence = page behavior" rule.
- Golden/profile tests: a multicast profile with and without the trio; the round-trip and the
  native parse.

Do **not** use the diting defaults (0x1000/0x20) for a 246 profile: the trio is per-build and, for
246, must come from the scan. The native `geometry_from()` already refuses a non-multiple grid or a
stride below the fake `rt_mutex` size.

### 4.3 The anchor gate (do this first)

Run (2026-10-21, `--iomem /dev/null`, the 5x extractor):

- 177 candidates; the named `dump_skip.zeroes` is **unsafe** (safe length 0x440, stopped by a live
  write at +0x2ec8018).
- The scan's top candidate, `rsc_seq_file` (image **+0x2d7e048**, extent **0xa2c00**, 0 live
  reads/writes, verdict **safe**), was **rejected after a QEMU provenance check**. It is 8 bytes
  after `rsc_slowpath_spinlock`, among `rsc_seq_alloc_num`/`rsc_seq_spinlock`/`rsc_slowpath_*`
  state; 952 rsc symbols fill `[__bss_start, +0x2e20c48)`, and the driver's probe/init runs in the
  guest (`rsc_main_pdrv_probe: rsc probe done`, `RSC rsc driver init done!`). The 16-byte zero read
  at boot only says the `seq_file` was not touched then; a live driver's `.bss` is not an anchor.
- The leading alternative is the **`dump_skip.zeroes` safe prefix**:
  `lock_anchor_image = 49052632` (0x2ec7bd8), safe length **0x440** (the first read is +0x428, the
  first store +0x440), `lock_anchor_bytes = 1024` (0x400 = 32 slots at stride 32),
  `lock_anchor_stride = 32`. The first 0x400 bytes have **no references at all**; the static search
  found no stored pointer to the symbol or into the prefix (the only 4-byte hit is the kallsyms
  table entry), and the QEMU guest read 80 bytes sampled across the prefix after driver init — all
  zero.
- The symbol's **overall verdict is `unsafe`** (the store at +0x440). Using its safe prefix is a
  deliberate use of the anchor-derivation quantity (the longest byte range with no live store), not
  the scan's verdict; the operator approved it on 2026-10-21 (image 0x2ec7bd8, bytes 0x400, stride
  0x20). The extractor's automatic `--anchor` path refuses the symbol and emits nothing — the
  profile must carry the reviewed triple explicitly.
- The QEMU check is boot-time only (1 CPU, no vivo hardware/Android userspace); runtime-computed or
  indirect writes are not covered. The static search is clean, but the operator's review is the
  gate, not the word "safe".
- The full candidate list (2026-10-21: 177 candidates, 72 safe / 31 needs-review / 74 unsafe)
  found **no better candidate**. The large `safe` rows outside the rsc range are live subsystem
  statics whose computed-index access the scan cannot see: `qos_tentry` is still rsc QoS,
  `sel_netnode_hash` is SELinux's netnode hash, and `s_uidSlaTcpInfo`, `constraint_attrs`,
  `snd_minors`, `inet_addr_lst` and `inet6_addr_lst` are vendor/core tables. The needs-review rows
  (`vsock_connected_table`, `reserved_mem`) have live reads. "Safe" is not "unused"; the
  `dump_skip.zeroes` prefix remains the only candidate.
- The operator approved the prefix on 2026-10-21; the implementation follows §7. Do not substitute
  the payload page and call it A-mechanism, and do not ship a 246 profile with an unverified
  anchor.

The scan and its verdict belong in the plan's evidence record before the first code commit.

### 4.4 Per-stage scope

| stage | request | stamp value | page content after this build |
|---|---|---|---|
| W1 SELinux | Zero, `preserve_child=true` | `page_base + 0x100` (address only) | **no** — lock anchor + init_task |
| W2 cred | Credential | `init_cred_alias`; `fops`/cred copy still page-based | **yes** — out of scope; audit separately |
| W3 seccomp | Zero, leaf (`preserve_child=false`) | `pc = target - 8` | **no** |

W1 is the observed vivo failure and the build's gate. W2's credential copy is a separate page
consumer; this plan does not claim to remove it. W3 already uses the leaf layout.

### 4.5 HIDP fallback

If the 246 anchor gate fails, the page-free candidates reduce to HIDP `HIDPGETCONNINFO` (measured:
Σ0x380, L=0x94, covers 0x2ec–0x380; the route's field window 0x2f0–0x330 is covered; the
`deadline` word + padding, 0xc, is not). It is conditional on two binary gates: an untrusted app
must be able to open an AF_BLUETOOTH/HIDP socket on that device, and the live waiter's
kernel-initialized `deadline` must already be 0 (the route stamps 0). HIDP needs the same anchor
mechanism for its lock, so it does **not** rescue a failed anchor gate unless its own lock source is
addressed. If the anchor exists but multicast's race proves unworkable, HIDP is the alternative
carrier.

## 5. Non-goals

- No change to the multicast carrier, its copy geometry, the consumer race, or the execution
  timing knobs.
- No change to the W1 verify path or the `status=0` semantics.
- No fully page-free W1 value in this build (see §3).
- No W2 credential-copy redesign.
- No new carrier; HIDP is the fallback decision, not an implementation here.
- No bundled 246 profile and no device-gated claim. The profile remains an imported, untested
  candidate.

## 6. Risks and open questions

1. **The 246 anchor is not settled.** `rsc_seq_file` is rejected (active rsc driver block), and
   the full candidate list found no better region — the alternatives are live subsystem statics.
   The `dump_skip.zeroes` prefix is the only candidate (0x2ec7bd8, 0x400/0x20, boot-zero, no refs),
   but its symbol verdict is `unsafe` and the choice needs the operator's explicit approval. A
   wrong anchor is a kernel crash.
2. **`init_task` as the waiter's task.** The TCP route already does this, but the PI walk takes
   `init_task`'s `pi_lock`; the select route's fake task exists to avoid exactly that. The build
   must show, on the diting's unit harness and then on a 246 device, that the init_task path does
   not deadlock or perturb the walk.
3. **The tree stamp's page-address value.** W1 uses `page_base + 0x100`; the `accepts_page` gate is
   address-based, so the page content no longer needs to be ours, but the page address must be a
   valid, writable scratch. This is unchanged from the diting's option 2 and must be stated in the
   evidence, not assumed.
4. **W2 remains page-based.** A successful W1 does not prove the chain; W2's fops/cred copy can
   still fail on the same device.
5. **Device availability.** The only carrier-feasible device is the reporter's 246 vivo. The diting
   cannot run multicast (0x48 short on 5.10.236). The 6.1 POCO was checked on 2026-10-21: its
   multicast copy depth 0x338 vs strip home 0x1e8 gives `waiter_off 0x150`, short by 0x88 in the
   window rule (0x48 in the address view), so the anchored multicast cannot run there either; its
   shipped tcp/select routes are unaffected, and the 6.1 anchor search found no safe candidate
   (`dump_skip.zeroes` absent; the large candidates live). The host gate is possible; the device
   gate is the 246.
6. **Profile-schema risk.** The anchor trio is per-route, per-build data; a wrong value is a kernel
   crash. The decoder must not fall back to the diting's defaults for a 246 profile.
7. **The route's weak success signal** (`setsockopt == 0 || consumer_success > 0`) means a clean
   route log is not a write. Do not use the route status as the gate; use the backend's verify.

## 7. Implementation steps (commit-sized)

1. `feat(profile): carry the lock-anchor trio on the multicast route` — Kotlin config, native
   layout/geometry wiring, binary rows, schema docs, round-trip tests. No route change.
2. `feat(route): stamp the full waiter for the anchored multicast route` — encoder call, anchor
   acquisition, init_task task, family-gated prio, route logs, unit tests (fit/refusal, word
   placement, anchor/no-anchor selection, `0` anchor fails the route).
3. `feat(extract): emit the multicast anchor and its verdict` — only if the anchor gate passes;
   route-aware emission, the 246 scan record, extractor tests.
4. `test(route): pin the multicast stamp against the select/sigreturn vectors` — the shared
   `waiter_words` definition must not drift between the three routes.
5. Gates and the device-gate plan (see §8).

Each commit must be separately reviewable, and the profile/schema commit lands before the route
commit so the route never reads a field the schema cannot express.

## 8. Gates and test plan

Host (the project's standing gates):

- `make -C src ghostlock` — zero warnings.
- `make -C src lint-tidy` — exit 0.
- `make -C src native-host-tests` — the 27 binaries.
- `tools/cmp_disasm.py` — attack-path gate; record the per-target counts.
- `payload_builder` unit vectors: the eleven-word placement, the `0x88 ≤ 0x108` fit, an undersized
  buffer refusal, and the anchor/no-anchor branch.
- Profile tests: Kotlin round-trip, native binary parse, golden multicast profile with and without
  the trio, and a refusal when `waiter_off + lock_offset + 8 > buffer_size`.

App/extractor (only if step 3 lands):

- `./gradlew --offline :app:assembleDebug`; Kotlin tests (the known
  `ProfileMigrationEquivalenceTest` failure is pre-existing).
- `cargo test` in `tools/extract_rs` (64 unit + the 14-image integration).

Device (blocked until a 246 device is available):

- One run per fresh boot, the reporter's device, the same W1 shell checks the vivo triage defined.
- The A/B is the current page route versus the anchored route on the same build, with the anchor
  value fixed by the scan; no identical runs on the same boot.
- The run store's `meta` and the W1 verify are the verdict; the route's `status=0` is not.
- The 246 profile is not bundled and not marked supported until this gate passes.

## 9. Evidence and records

- This plan: `docs/analysis/multicast-anchor-plan.md` (this file).
- The anchor scan's verdict (2026-10-21): `rsc_seq_file` image +0x2d7e048, safe length 0xa2c00,
  zero direct references; `dump_skip.zeroes` unsafe (safe length 0x440, live write at +0x2ec8018).
  The raw scan text is in the port's private 246 session; the conclusion is stated here.
- The route unit-test vectors and the host gate logs.
- If a device run happens, one run directory per fresh boot with the stream, dmesg/kmsg, and the
  run store's `meta`; the project's existing evidence rules apply.

## Appendix A — numbers

- 246: futex `0xe0+0xc0+0x1b0 = 0x350`; strip home `0x330`; setsockopt `0x380`, greqs sp+0x20 →
  `0x360`; `waiter_off 0x30`; buffer 264; task `+0x30`, lock `+0x38`, prio `+0x40`, deadline
  `+0x48`; `kWaiterBytes 0x58`; `0x30 + 0x58 = 0x88 ≤ 0x108`.
- Diting anchor control: `dump_skip.zeroes` image +0x2a3a590, 0x1000 bytes, stride 0x20, 128
  slots; direct map `0xffffff802aa3a590`; boot-invariant.
- 246 named anchor: `dump_skip.zeroes` +0x2ec7bd8, safe length 0x440 — unsafe (not usable).
- 246 scanned anchor (rejected after QEMU): `rsc_seq_file` +0x2d7e048, safe length 0xa2c00, 0
  direct references, but inside the active rsc driver's `.bss` block.
- 246 leading candidate: `dump_skip.zeroes` safe prefix, +0x2ec7bd8, safe length 0x440; first read
  +0x428, first store +0x440; 0x400/0x20 (32 slots); boot-zero sampled; **approved 2026-10-21**.
- 246 full candidate list: 177 candidates, 72 safe / 31 needs-review / 74 unsafe; no better
  candidate (the outside safe rows are live subsystem statics, e.g. `qos_tentry` is rsc QoS,
  `sel_netnode_hash` is SELinux's netnode hash).
- `kernel_phys_load = 0xA8000000` (firmware memory map; already in the run profiles).

## Appendix B — code references

- `src/core/route/multicast_waiter_route.cpp`: route, geometry refusal (step 58), two-word stamp
  (line 44), socket/setsockopt/consumer, status line.
- `src/core/memory/payload_builder.h`: `kWaiterBytes`, `WaiterWords`, `waiter_words()`,
  `encode_waiter_words()`; `payload_builder.cpp`: `encode_multicast_waiter()` (the two-word
  encoder to replace), `payload_write_layout()`, `payload_write_layout_accepts_page()`.
- `src/core/route/lock_anchor.{h,cpp}`: the grid and `acquire_lock_word()`; the attempt is log-only,
  `allocate_slot()` is the boot serial.
- `src/core/route/select_stack_route.cpp:466-491`, `sigreturn_route.cpp:431-457`: the anchor branch
  and the `waiter_words` call to mirror.
- `src/core/profile/model.h`: `MulticastWaiterLayout` (line 178), `multicast_layout()` (line 360),
  the shared `RouteGeometry` anchor members (line 140), `SigreturnLayout` (line 205).
- `src/core/profile/binary.cpp`: `kRouteSelect`, `kRouteMulticast`, `kRouteSigreturn` (around line
  183).
- `profile-core/src/main/kotlin/com/ghostlock/app/data/route/{MulticastConfig,SelectConfig}.kt`.
- `src/core/session/backend/cve_2026_43499_backend.cpp`: `retry_write_stage()` (line 43), W1
  `mode=1, leaf=0` (line 503), `w1_attempts=1` for multicast (line 497).
- `src/core/route/tcp_zerocopy_route.cpp:265-266`: `slide_init_task()` as the waiter task precedent.

## Appendix C — why not just reuse the select anchor keys

The sigreturn route already duplicates the anchor trio in its own section, with the explicit
comment that the decoder never merges across routes. Reusing `route.select_stack.lock_anchor_*` from
a multicast profile would make the profile's anchor depend on a section the route does not select,
and the Kotlin merger/renderer would not round-trip it. The multicast section gets its own keys; the
native storage stays shared (`select_lock_anchor_*` members), as sigreturn's already is.
