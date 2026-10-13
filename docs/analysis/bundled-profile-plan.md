# Bundling the diting profile — and stopping a stale one from running

Status: **rationale record, implemented 2026-10-09.** The binding specification is `PORT-PLAN.md`
Phase 8 in the project root — **read that first**, and its *Implementation status* for what landed;
this file explains why the design is shaped the way it is. Its "Steps" section and the G1/G2/G3
sketch below are the **pre-implementation** design and are kept only as the reasoning trail; two
things in them turned out differently, and both are corrected in place below. L-level: it touches
the asset→Kotlin→wire profile contract.

**Superseded in one respect.** This file proposed a one-shot, versioned *migration* that would
quarantine the user layers on upgrade. That was replaced: a migration only fixes the layers present
at the moment it runs, cannot stop one reintroduced afterwards, and cannot stop a shipped parameter
change being shadowed by an old import. The adopted design makes the bundled profile authoritative
and simply *does not apply* the layers that would shadow it — no generation integer, no file moves,
nothing deleted. Fourteen requirements of migration machinery disappear with it.

## Why bundle

The profile ships today as a release asset the user must download and import by hand. Everything
downstream of that is a failure mode we have already paid for:

* the import step has a file picker, and the picker offered three near-identical confs (two stale)
  until the Download folder was cleaned by hand;
* nothing points a user at *where* the conf lives — the app says "import it in Parameters", not
  "it is next to the APK on the release page";
* a user on a different kernel can edit the one `release = "…"` line and convert a clean refusal
  into a silent run on our offsets.

Bundling removes all three. It also makes `kernel uname` the *selector*: a device on another build
gets "Not supported" rather than an invitation to import a mismatched file. That is the actual fix
for the cross-build reports.

The mechanism already exists — upstream ships 67 builtin profiles in
`app/src/main/assets/kernel_profiles/` with an `index.conf`, loaded by `BuiltinProfileCatalog`, and
`AndroidGhostlockRepository.kt:919` counts a device supported when
`version in builtinProfiles.unames || importedOffsetsMatch(version)`. Our kernel is simply not
registered.

## There is no blocker — corrected 2026-10-09

An earlier version of this file (and the session note it came from) claimed bundling was blocked by
`routeFieldKey()` needing names for the three anchor keys. **That was wrong**, and it is worth
recording why, because the wrong version would have sent someone to edit shared code for nothing.

`routeFieldKey()` belongs to `BuiltinProfileCatalog.flatten()`, and **the flat map it produces is
never read**. Verified: `builtinProfiles.builtin` has no reference outside its own class, and
`state.builtinProfiles` is a `List<String>` of release names. `flatten()` exists only to compute
`recommend_shizuku`. The anchor keys falling through to the generic `"$route.$field"` branch is
therefore harmless — nothing consumes that branch.

The **real** builtin resolution path is `AndroidProfileConfigController.resolve()`:

1. `readIndex()` parses `index.conf` → `profiles = [ { release, file }, … ]`
2. `findProfile()` matches the index entry whose `release` equals the active profile release
3. it parses `assets/kernel_profiles/<file>` as HOCON, requires `schema_version == 1` and
   `release == entry.release`, and merges **that** as the `builtin` layer

So a builtin profile is a **plain HOCON document, byte-for-byte the same shape as an imported user
document** — which is exactly what our conf already is. Everything we rely on, the anchor keys
included, flows through the same merge code that has been handling the imported document correctly
all along.

Bundling is therefore: **copy the conf into the assets directory, and add one `index.conf` entry.**
No Kotlin change, no contract change, no `routeFieldKey` edit.

## How a stale profile slips into a run

The merge order is the root of it (`ProfileMerger.resolve`):

```
defaults  ←  builtin  ←  imported  ←  overrides
```

so an imported document **outranks** a bundled one, and the debug overrides outrank both. Four
concrete paths:

1. **A previously-imported document shadowing a newer builtin.** `PrefActiveUserProfile` is a
   preference and survives `install -r`. A user who selected an imported profile once keeps
   overriding the bundled one forever — including after we ship a corrected builtin. Nothing says so.
2. **`debug_profile_overrides` outranking everything, invisibly.** This one bit us *today*: a
   `setup_settle_us = 50000` injected to force a failure, whose only safeguard was remembering to put
   it back. It has no expiry, no UI, and no line in the run log.
3. **The resolved-profile snapshot cache** (`cache(...)`, `persistSnapshot`), if it is ever reused
   without re-resolving after a layer changes.
4. **App updates preserve prefs and `files/`.** Only a clean install resets anything.

## The guards

**G1 — a digest of the effective profile, checked end to end.** *Corrected at implementation: the
claim below that it "catches every stale path above at once" is **wrong**, and the shipped comment
says so. Staleness resolves to the same document on both sides of the wire, so both hash it equally
and the digest passes. What it does catch is a **dropped key** — a key one side declares and the
other does not, which is the failure this fork actually hit — plus a mangled or truncated payload.
Stopping stale layers is §B's job, not the digest's; §B and §C were implemented first for that
reason.* It remains a *detector* rather than a policy, which is why it is worth carrying alongside
the policy.

* Kotlin computes a 64-bit digest over the canonicalised resolved profile (sorted key→value pairs)
  when building the GLK1 wire.
* It travels as an ordinary **section entry** — sections are `name → {key: u64}` and a 64-bit digest
  is exactly a u64, so **this needs no wire-format change and no reserved-field scavenging**. Unknown
  sections are ignored by older natives.
* Native recomputes the same digest over what it decoded and compares. **Mismatch is fatal**, not a
  warning, and both values are logged.
* The log line names the layers, so a remote log says what ran and where it came from:
  `profile digest=… release=… sources=[builtin, imported:<name>, overrides:N]`

**G2 — the overrides layer becomes visible.** Log its keys at run start, and surface in the UI that
overrides are active. Cheap, and it closes the hole that caught us today.

**G3 — shadowing is announced.** At resolve time, when an imported layer shadows a builtin for the
same release, log it and show it. A profile generation key would let a builtin declare itself newer
than what the user imported; that is the next step if G1 proves noisy in practice.

**G2/G3 as built, and the start-up dialog added after the device gate.** The run log carries one
`profile layers:` line naming every layer and why it did or did not apply (§C.10-11), and the profile
screen shows a banner for each inactive layer. That banner turned out to be **too buried to be the
only surface**: the user it exists for — someone who just upgraded with an import and overrides in
place — has no reason to open that screen, so in practice they never learn that their settings
stopped applying. So on the first start after the layers go inactive the app raises a **dialog with
one confirm button** naming what was disabled and why (PORT-PLAN §C.12a).

**Why it is a report and not a promise (§C.12b).** The dialog is built from the `ProfileLayers`
object of the *resolution that just ran* — the same object the run path and the editor read — rather
than from a second predicate the UI evaluates for itself. Two properties follow, and both are
tested: what the dialog says is exactly what a run would do at that moment (the layers are already
inactive, not scheduled to be), and the two can never disagree, which a recomputed predicate would
eventually. It fires **once per build identity** (the acknowledgement is persisted, and a new build
is a new identity), so it cannot nag; the banner stays for every later visit and for anyone who
dismisses the dialog without reading it.

## Steps

*Superseded by the §B–§F implementation; kept as the record of what was planned. Step 1 was
withdrawn — `routeFieldKey` is dead code, see "There is no blocker" above.*

1. ~~Decide the canonical flat names for the three anchor keys and extend `routeFieldKey`.~~
2. Add the diting conf to `app/src/main/assets/kernel_profiles/` and register it in `index.conf`.
3. Rebuild the asset copy from the same source as the released conf — one source, not two.
4. Implement G1 (Kotlin digest + wire section; native recompute + fatal compare + log).
5. Implement G2 and G3 (logging and UI).
6. Gates, then a device run proving the anchor specifically survives the builtin path.

**What was built instead, and where:** the layer policy and the run-log reporting (§B/§C) come
first because they are what actually stop a stale layer; the digest (§E) is the detector, with its
scope stated in both implementations; the cache (§F) and the build identity (§D) support §B.7.
`AndroidProfileConfigController.resolve()` is the single place the layer decision is made, and
`ProfileLayers` (in `GhostlockModels.kt`) is what the log and the UI read.

## Gates

`make -C src ghostlock` 0 warnings · `make -C src lint-tidy` exit 0 · the Kotlin round-trip test
extended to the builtin path · `tools/cmp_disasm.py` (the native profile decode is on the attack
path) · a device run with the log showing the digest matching and the anchor in use.

## Open decisions

* Whether the three anchor keys should be **upstreamable** — the extension touches shared code with
  fork-specific keys, so the asset would be fork-only until the anchor is upstreamed.
* Whether G3 should be policy (builtin wins over an older import) or only a warning. Policy changes
  behaviour for a user who legitimately tuned their own profile.
