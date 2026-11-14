# The unreadable external selection — reporting, not policy (M-level rationale)

Level: **M** — app-only Kotlin (snapshot field, home status card, one toast, one typed layer
fact). No native, wire, profile-schema or route change; no device run is needed to design it, and
the host gates plus one device check are the acceptance.

**Status 2026-11-14.** Implemented (uncommitted on `document`); host gates green
(`:app:testDebugUnitTest` 244/0, `:profile-core:test`, `assembleDebug` 748) and the device
acceptance passed on the diting: with the selected document deleted the home reads 配置无法读取 /
请在配置参数中重新选择外部配置文件, the card opens 参数配置 → 加载配置 with the source warning, and
re-selecting the file restores 受支持 with the same reference. The inode-swap break did not
reproduce on this ROM (the provider follows the path); the removal is the local reproduction.
Record: `external/port/external-profile-unreadable-2026-11-14/`.

## The measured case

2026-11-12, the duchamp (G2; `external/port/compat-multicast-2026-11-12/g2-v4/`): the selected SAF
document stopped opening. The Downloads provider pins the document by inode, and an earlier
`adb push` restore had replaced it — the row exists, the URI resolves, but `openInputStream`
fails. The loader's behaviour is right and stays: **an unreadable external selection is an error,
never a silent fallback to the bundle**. The profile is the attack configuration; substituting a
different route behind the user's back would be worse than no profile at all.

What was wrong is the report:

- `releaseSupportedByProfileSources()` counts the stored selection's *recorded release*, so
  `kernelKnown` stayed true while `load()` returned no profile.
- On the MTK rig the snapshot then set `devicePairMissing` (`kernelKnown && !usable`), so the home's
  status card — which tests `!supported` first — read **不支持 / 未找到匹配的内核配置**. The user is
  sent hunting for a kernel/profile match instead of re-selecting the one file whose read failed.
- On a Qualcomm rig the same state reads **需要加载配置**, also wrong: a profile *is* selected.
- The real reason existed only in 配置参数 → 配置来源 (`无法读取所选文档，请重新选择或取消选择`) and in
  the once-per-build start-up layer notice. There was no repair action on the home.

## The change

1. **A typed fact.** `ProfileLayers.externalReadFailure` is set only when the selected document
   itself could not be read (`cannot read <name>`). A readable document that fails its content
   checks (no entry for the release, bad fields) keeps `externalError` but leaves the new flag
   false — those failures have a different repair.
2. **The snapshot discounts it.** `KernelSnapshot.externalProfileUnreadable` carries the fact, and
   `snapshot()` computes `kernelKnown = coveredByStoredSource && !externalReadFailure`. The stored
   selection's release is a *candidate* until its document is readable; while it is not, the badge
   is unsupported — exactly what the resolver does. `devicePairMissing` stays false (the pair is
   not the problem), and `isKernelSupported()` is renamed `releaseCoveredByStoredSource()` so the
   two roles cannot be confused again.
3. **A distinct home state.** The status card tests `externalProfileUnreadable` before its
   unsupported branch: 配置无法读取 / Profile unreadable, summary 请在配置参数中重新选择外部配置文件 /
   Re-select the external profile file in Parameters, error container, and the tap goes to the
   config screen (not the Shizuku action). 执行 stays disabled — the run path is untouched.
4. **Accurate prose where the user meets the block.** The run-button overlay toast says the external
   profile cannot be read; the run log (if it is ever reached) says the same instead of "unsupported
   by this kernel".

The config-source screen already shows the selection's name and the `无法读取所选文档` warning banner
(it keys on `externalError != null`), so it needs no change; the home now points at it.

## Why not the alternatives

- **Fall back to the bundle when the external document is unreadable.** Rejected: it hides the
  user's broken selection and silently changes the attack configuration.
- **Drop the selection automatically.** Rejected: destructive without consent; the repair is one
  picker tap and the reference must survive so the user can see what failed.
- **Treat "no entry for this release" the same as a read failure.** Rejected: that document is
  readable; telling the user to re-select it is wrong. It keeps the existing `externalError` path.

## Gates

- Host: `:app:testDebugUnitTest` (the new `ProfileLayerPolicyTest` cases: the read-failure flag is
  set for a missing source, clear for a wrong-release document, and the same selection applies again
  once the file returns), `:profile-core:test`, `assembleDebug` with zero warnings.
- Device (acceptance): on a rig with an external selection, break the document (or use the known
  inode-swap state), confirm the home reads 配置无法读取 with the action landing on 配置参数, then
  re-select the same file and confirm 受支持 / 执行 enabled. No attack run is required for the
  reporting path; a normal run after re-selection is the regression check.
