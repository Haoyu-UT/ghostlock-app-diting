# DirtyFrag stage 1 — static checks, results

**Status:** done 2026-11-08 (host-side only; no device was touched). Parent design:
`dirtyfrag-samsung-second-route-plan.md`. This document records what the two target images and
their ROM libraries say; it does not change any code.

## What was checked, and against what

| target | kernel | source of truth |
|---|---|---|
| diting (Xiaomi.eu `OS3.0.3.0.VLFCNXM`) | `5.10.236-android12-9-00003-gfb24cf99ad97-ab14313284` | the stock `Image` extracted from the device's own `boot.img` |
| Samsung A16 (`SM-A165MUBS6CYL1`) | `6.12.23-android16-5-abA165MUBS6CYL1-4k` | `Image.raw` from the official firmware |

Both version strings were read out of the images and match verbatim. The libraries are the
**ROM packages'** copies (`/system/lib64/libc++.so`, `/system/lib64/libbase.so`), pulled out of the
super images offline — not pulled from a running device. The diting library therefore comes from
the same build the rig runs, but stage 2 will confirm the installed copy.

## The fix

Upstream `f4c50a4034e62ab75f1d5cdd191dd5f9c77fdff4` ("xfrm: esp: avoid in-place decrypt on shared
skb frags"), 5.10 backport `a6cb440f2`, first released in **v5.10.255**. It has three parts:

- `ip_append_page()` marks spliced datagram frags with `SKBTX_SHARED_FRAG`;
- `esp_input()` / `esp6_input()` add `!skb_has_shared_frag(skb)` to the no-COW fast path.

`skb_has_shared_frag()` is an inline test of a `skb_shared_info` flag, so the fix adds no symbol;
the image check is instruction-level.

## Results

**1. Both kernels are vulnerable.** In the diting `esp_input` the uncloned/nonlinear fast path is
`data_len != 0` → `frag_list == NULL` → `skip_cow`, with no `tx_flags`/`SKBTX_SHARED_FRAG` test
between the `frag_list` test and the branch; `esp6_input` is identical. The A16 `6.12.23` build has
the same shape in both functions (`data_len` → `frag_list` → `skip_cow`, no shared-frag test). Since
the ESP half of the fix is absent, externally-backed frags are decrypted in place regardless of
whether the send path marked them.

**2. The configs allow the route.** Both images embed their config and declare
`CONFIG_INET_ESP=y`, `CONFIG_INET6_ESP=y`, `CONFIG_XFRM=y`, `CONFIG_XFRM_USER=y`, `CONFIG_IPV6=y`
and the AES-CBC/HMAC-SHA256 primitives built in — nothing has to be loaded.

**3. The send side is present.** The diting image carries the 5.10 splice path
(`inet_sendpage`/`udp_sendpage`/`ip_append_page`). The A16 `__ip_append_data` calls
`skb_splice_from_iter` in its `MSG_SPLICE_PAGES` branch, and `iov_iter_extract_pages` is present.

**3b. No bridge needed.** In both images `/system/lib64/libc++.so` is a `0644` regular file owned
by `uid 0/gid 0`, so the app can open and splice from it directly. DFRoot's
`splicehelper → crash_dump64` bridge exists to reach `vendor_file`-labelled files (its `.ko`) and
to read them back; the module-free shape does not need it, and it stays a fallback-only dependency.

**4. The libc++ hook target exists on both ROMs.**

| | symbol | first insn | cave for DFRoot's 480-byte blob |
|---|---|---|---|
| diting libc++ | `_ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE6sentryC1ERS3_` | `BTI c` | tail page: 2520 B slack |
| diting libbase | `_ZN7android4base10LogMessageD1Ev` | `PACIASP` | tail page: 2256 B |
| A16 libc++ | same mangled name | `BTI c` | tail page: **640 B** |
| A16 libbase | same mangled name | `sub sp, sp, #0x70` | tail page: 1200 B |

The zero-run fallback cave does not exist on any of the four (4–12 bytes at most): only the
tail-page placement works, which is DFRoot's first choice anyway. DFRoot's shellcode is 468 bytes,
padded to 480.

**Two consequences for the design.** On both libc++ builds the executable segment ends exactly
where the RW segment's file data begins, so the tail cave is page-shared with the RW `PT_LOAD`:
the write is visible to the already-running init mapping (its exec tail page is not COWed), but it
corrupts the page-cache copy of the RW start for any later process that maps the library. That is
consistent with DFRoot's soft-reboot model, but the hybrid must either restore the bytes or state
the trade. And the A16 margin is thin — 160 spare bytes — so an adapted stub must stay under
~600 bytes there (libbase's 1200 B is the roomier fallback).

**4b. The init hook's call path is statically present.** On both ROMs `init` and `libbase.so`
import libc++'s exported sentry constructor (`_ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE6sentryC1ERS3_`)
in their undefined dynsym, so init's logging reaches the patched function through the PLT. A scan
of libc++.so's own executable segment finds no *direct* BL to that exported constructor (an
internal caller could still use a PLT stub or be inlined), so the hook's reliable firing rests on
external PLT callers — and they exist on both builds. init's `sigchld_handler.cpp` reap path also
carries its log strings on both binaries ("pids to be reaped took"), which is the orphan-reap
trigger DFRoot uses. The app seccomp allowlist itself was not checked from the ROM (it is compiled
into the runtime APEX; the earlier survey records `splice` as allowed) — stage 2 confirms it on
the device.

## What is still open

- **Stage 2** (the decisive non-escalating page-cache write/read-back on the diting) is deferred:
  the device is in operator use. It also confirms the installed library matches the ROM copy.
- Anything ROM-side that could act as an accidental mitigation (DFRoot's FAQ mentions 6.1) is not
  visible statically on `6.12.23`: the ESP check is absent and the datagram splice path attaches
  pages. SELinux/IpSec reachability belongs to stage 2.
- The module fallback's KMI/vermagic is not checked — the adopted shape is module-free, and the
  module is only the DEFEX fallback.
