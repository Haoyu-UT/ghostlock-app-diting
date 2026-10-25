//! Per-field structure derivation for 5.10 images without BTF.
//!
//! Every field is read from the image itself:
//!
//! - `init_task` is a statically initialised `task_struct`, so its `comm`
//!   string, its `init_cred` pointers, the `root_task_group` pointer and the
//!   `prio`/`static_prio`/`normal_prio` run locate those fields directly.
//! - `copy_process` writes `pid`/`tgid`, initialises the PI fields and links
//!   the new task into `init_task.tasks`; those stores locate the remaining
//!   fields without a hardcoded offset.
//! - `init_cred` carries the capability mask and the reference pointers; the
//!   scan is bounded by the series `cred` copy size so neighbouring data is
//!   not mistaken for a reference.
//! - `__secure_computing` loads `current->seccomp.mode` and `copy_seccomp`
//!   moves the whole `struct seccomp`; either anchors the `seccomp` field.
//!   The disassembler spells SP_EL0 as `s3_0_c4_c1_0`, not the `sp_el0` alias.
//!
//! A field is emitted only when its anchor is unique. A miss is left absent:
//! the caller then falls back to the measured-series template (inside the
//! IKCONFIG fingerprint) or to null. No value from a neighbouring release is
//! guessed.

use std::collections::{BTreeMap, BTreeSet};

use regex::Regex;

use crate::derive::{disassemble_symbol, Cred5x, RelSymbols};
use crate::family::{CRED_COPY_SIZE, KIMAGE_TEXT_BASE};

/// `init_task` is a little over 0x1000 bytes; 0x2000 covers the fields read
/// here and any padding the linker leaves before the next object.
const INIT_TASK_SCAN: usize = 0x2000;
const COPY_PROCESS_CAP: usize = 0x2000;
const CAP_FULL_SET: u64 = 0x1ff_ffff_ffff;

const CAPS_SLOTS: usize = 5;
const REF_LIMIT: usize = 4;

/// Fields recovered from the image, with the anchor that proved each one.
#[derive(Default, Debug, Clone)]
pub struct DerivedStructs {
    pub values: BTreeMap<&'static str, u32>,
    pub sources: BTreeMap<&'static str, &'static str>,
}

impl DerivedStructs {
    fn insert(&mut self, name: &'static str, value: u32, source: &'static str) {
        self.values.insert(name, value);
        self.sources.insert(name, source);
    }

    fn extend(&mut self, other: DerivedStructs) {
        for (name, value) in other.values {
            self.values.insert(name, value);
            if let Some(source) = other.sources.get(name) {
                self.sources.insert(name, source);
            }
        }
    }
}

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn u64_at(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

/// The fields readable straight out of `init_task`.
pub fn derive_from_init_task(
    chunk: &[u8],
    init_cred_va: u64,
    root_task_group_va: u64,
) -> DerivedStructs {
    let mut out = DerivedStructs::default();

    /* comm: the kernel's bootstrap task name, 16-byte field, 8-aligned. */
    let names: Vec<usize> = chunk
        .windows(b"swapper".len())
        .enumerate()
        .filter(|(_, window)| *window == b"swapper")
        .map(|(index, _)| index)
        .collect();
    if names.len() == 1 {
        let offset = names[0];
        if offset % 8 == 0 {
            let field = chunk.get(offset..offset + 16);
            let closes = field.is_some_and(|field| {
                field.iter().any(|byte| *byte == 0)
                    && field
                        .iter()
                        .take_while(|byte| **byte != 0)
                        .all(|byte| byte.is_ascii_graphic() || *byte == b'/')
            });
            if closes {
                out.insert("task_comm", offset as u32, "init_task:comm");
            }
        }
    }

    /* real_cred/cred: two adjacent pointers to init_cred. */
    if init_cred_va != 0 {
        let slots: Vec<usize> = (0..chunk.len().saturating_sub(8))
            .step_by(8)
            .filter(|offset| u64_at(chunk, *offset) == Some(init_cred_va))
            .collect();
        if slots.len() == 2 && slots[1] == slots[0] + 8 {
            out.insert("task_real_cred", slots[0] as u32, "init_task:real_cred");
            out.insert("task_cred", slots[1] as u32, "init_task:cred");
        }
    }

    /* sched_task_group: the only pointer to the static root task group. */
    if root_task_group_va != 0 {
        let slots: Vec<usize> = (0..chunk.len().saturating_sub(8))
            .step_by(8)
            .filter(|offset| u64_at(chunk, *offset) == Some(root_task_group_va))
            .collect();
        if slots.len() == 1 {
            out.insert(
                "task_sched_task_group",
                slots[0] as u32,
                "init_task:root_task_group",
            );
        }
    }

    /* prio/static_prio/normal_prio: three equal 32-bit priorities. The middle
     * field is static_prio; the profile carries the outer two. */
    let mut runs = Vec::new();
    let mut cursor = 0usize;
    while cursor + 12 <= chunk.len() {
        let first = u32_at(chunk, cursor);
        if let (Some(first), Some(second), Some(third)) =
            (first, u32_at(chunk, cursor + 4), u32_at(chunk, cursor + 8))
        {
            if first == second && second == third && (100..=139).contains(&first) {
                let before = cursor.checked_sub(4).and_then(|at| u32_at(chunk, at));
                let after = u32_at(chunk, cursor + 12);
                if before != Some(first) && after != Some(first) {
                    runs.push(cursor);
                }
                cursor += 12;
                continue;
            }
        }
        cursor += 4;
    }
    if runs.len() == 1 {
        out.insert("task_prio", runs[0] as u32, "init_task:prio-run");
        out.insert("task_normal_prio", runs[0] as u32 + 8, "init_task:prio-run");
    }

    out
}

/// Addresses materialised by an `adrp` followed by a same-register `add`.
fn materialized_addresses(lines: &[String]) -> BTreeSet<u64> {
    let adrp = Regex::new(r"(?i)^\s*adrp\s+x(\d+),\s*0x([0-9a-f]+)\s*$").unwrap();
    let add = Regex::new(r"(?i)^\s*add\s+x(\d+),\s*x(\d+),\s*#0x([0-9a-f]+)\s*$").unwrap();
    let mut addresses = BTreeSet::new();
    for (index, line) in lines.iter().enumerate() {
        let Some(captures) = adrp.captures(line) else {
            continue;
        };
        let Ok(page) = u64::from_str_radix(&captures[2], 16) else {
            continue;
        };
        for next in &lines[index + 1..(index + 5).min(lines.len())] {
            let Some(candidate) = add.captures(next) else {
                continue;
            };
            if &candidate[1] != &captures[1] || &candidate[2] != &captures[1] {
                continue;
            }
            if let Ok(low) = u64::from_str_radix(&candidate[3], 16) {
                addresses.insert(page.wrapping_add(low));
            }
            break;
        }
    }
    addresses
}

/// The fields written by `copy_process`.
pub fn derive_from_copy_process(lines: &[String], init_task_offset: u64) -> DerivedStructs {
    let mut out = DerivedStructs::default();
    let ldr_pid = Regex::new(r"(?i)^\s*ldr\s+w(\d+),\s*\[x(\d+),\s*#0x60\]\s*$").unwrap();
    let str_w = Regex::new(r"(?i)^\s*str\s+w(\d+),\s*\[x(\d+),\s*#0x([0-9a-f]+)\]\s*$").unwrap();
    let str_zr = Regex::new(r"(?i)^\s*str\s+(w|x)zr,\s*\[x(\d+),\s*#0x([0-9a-f]+)\]\s*$").unwrap();
    let add_base = Regex::new(r"(?i)^\s*add\s+x(\d+),\s*x(\d+),\s*#0x([0-9a-f]+)\s*$").unwrap();

    /* pid: pid_nr(pid) is loaded from [pid, #0x60] and stored into the task.
     * Only a unique (register, offset) pair is accepted. */
    let mut pid_sites: BTreeSet<(usize, u32)> = BTreeSet::new();
    for (index, line) in lines.iter().enumerate() {
        let Some(load) = ldr_pid.captures(line) else {
            continue;
        };
        let word = &load[1];
        for next in &lines[index + 1..(index + 3).min(lines.len())] {
            let Some(store) = str_w.captures(next) else {
                continue;
            };
            if &store[1] != word {
                continue;
            }
            let (Ok(register), Ok(offset)) = (
                store[2].parse::<usize>(),
                u32::from_str_radix(&store[3], 16),
            ) else {
                continue;
            };
            pid_sites.insert((register, offset));
        }
    }
    let Some(&(task_register, pid_offset)) = pid_sites.iter().next() else {
        return out;
    };
    if pid_sites.len() != 1 {
        return out;
    }
    out.insert("task_pid", pid_offset, "copy_process:pid");
    let tgid_offset = pid_offset + 4;
    let tgid_written = lines.iter().any(|line| {
        str_w.captures(line).is_some_and(|store| {
            store[2].parse::<usize>().ok() == Some(task_register)
                && u32::from_str_radix(&store[3], 16).ok() == Some(tgid_offset)
        })
    });
    if tgid_written {
        out.insert("task_tgid", tgid_offset, "copy_process:tgid");
    }

    /* PI fields: rt_mutex_init_task zeroes pi_lock (wzr), then pi_waiters,
     * pi_top_task and pi_blocked_on (xzr) in that order. */
    let mut pi_sites: BTreeSet<(u32, u32, u32, u32)> = BTreeSet::new();
    for (index, line) in lines.iter().enumerate() {
        let Some(lock) = str_zr.captures(line) else {
            continue;
        };
        if &lock[1] != "w" || lock[2].parse::<usize>().ok() != Some(task_register) {
            continue;
        }
        let Ok(lock_offset) = u32::from_str_radix(&lock[3], 16) else {
            continue;
        };
        let mut zeroes = Vec::new();
        for next in &lines[index + 1..(index + 20).min(lines.len())] {
            let Some(store) = str_zr.captures(next) else {
                continue;
            };
            if &store[1] != "x" || store[2].parse::<usize>().ok() != Some(task_register) {
                continue;
            }
            if let Ok(offset) = u32::from_str_radix(&store[3], 16) {
                zeroes.push(offset);
            }
        }
        if zeroes.len() < 4 {
            continue;
        }
        /* 5.10's `struct plist_head` is one list_head (two words); pi_top_task
         * and pi_blocked_on follow it. The extra zero store at waiters+8 is
         * the list head's second word, not a field. */
        let waiters = zeroes[0];
        let top = zeroes[2];
        let blocked = zeroes[3];
        if lock_offset < waiters
            && zeroes[1] == waiters + 8
            && top == waiters + 0x10
            && blocked == top + 8
            && waiters - lock_offset <= 0x40
        {
            pi_sites.insert((lock_offset, waiters, top, blocked));
        }
    }
    if pi_sites.len() == 1 {
        let &(lock_offset, waiters, top, blocked) = pi_sites.iter().next().unwrap();
        out.insert(
            "task_pi_lock",
            lock_offset,
            "copy_process:rt_mutex_init_task",
        );
        out.insert(
            "task_pi_waiters",
            waiters,
            "copy_process:rt_mutex_init_task",
        );
        out.insert("task_pi_top_task", top, "copy_process:rt_mutex_init_task");
        out.insert(
            "task_pi_blocked_on",
            blocked,
            "copy_process:rt_mutex_init_task",
        );
    }

    /* tasks: copy_process links the new task into init_task.tasks. The field
     * is the `add <task>, <task>, #off` whose init_task+off address is
     * materialised in the same function. */
    let materialized = materialized_addresses(lines);
    let mut task_sites: BTreeSet<u32> = BTreeSet::new();
    for line in lines {
        let Some(add) = add_base.captures(line) else {
            continue;
        };
        if add[2].parse::<usize>().ok() != Some(task_register) {
            continue;
        }
        let Ok(offset) = u32::from_str_radix(&add[3], 16) else {
            continue;
        };
        if (0x300..=0xc00).contains(&offset)
            && materialized.contains(&init_task_offset.wrapping_add(offset as u64))
        {
            task_sites.insert(offset);
        }
    }
    if task_sites.len() == 1 {
        out.insert(
            "task_tasks",
            *task_sites.iter().next().unwrap(),
            "copy_process:list_add_tail",
        );
    }

    out
}

const SECCOMP_CAP: usize = 0x2000;

/// `__secure_computing` reads `current->seccomp.mode` as a 32-bit load off
/// `sp_el0`; `copy_seccomp` moves the whole 16-byte `struct seccomp`, usually
/// as a paired load. Either shape locates the `seccomp` field.
fn seccomp_mode_load(lines: &[String]) -> Option<u32> {
    /* The disassembler prints SP_EL0 by its encoding, s3_0_c4_c1_0. */
    let mrs = Regex::new(r"(?i)^\s*mrs\s+x(\d+),\s*(?:sp_el0|s3_0_c4_c1_0)\s*$").unwrap();
    let mov = Regex::new(r"(?i)^\s*mov\s+x(\d+),\s*x(\d+)\s*$").unwrap();
    let mut hits: BTreeSet<u32> = BTreeSet::new();
    for (index, line) in lines.iter().enumerate() {
        let Some(captures) = mrs.captures(line) else {
            continue;
        };
        let mut register = captures[1].to_string();
        for next in &lines[index + 1..(index + 12).min(lines.len())] {
            if let Some(copy) = mov.captures(next) {
                if &copy[2] == register.as_str() {
                    register = copy[1].to_string();
                    continue;
                }
            }
            let load = Regex::new(&format!(
                r"(?i)^\s*ldr\s+w\d+,\s*\[x{register},\s*#0x([0-9a-f]+)\]\s*$"
            ))
            .unwrap();
            if let Some(captures) = load.captures(next) {
                if let Ok(offset) = u32::from_str_radix(&captures[1], 16) {
                    hits.insert(offset);
                }
            }
        }
    }
    unique_seccomp_offset(&hits)
}

fn seccomp_struct_copy(lines: &[String]) -> Option<u32> {
    let mrs = Regex::new(r"(?i)^\s*mrs\s+x(\d+),\s*(?:sp_el0|s3_0_c4_c1_0)\s*$").unwrap();
    let load =
        Regex::new(r"(?i)^\s*(?:ldr|ldp)\s+x\d+(?:,\s*x\d+)?,\s*\[x(\d+),\s*#0x([0-9a-f]+)\]\s*$")
            .unwrap();
    let mut hits: BTreeSet<u32> = BTreeSet::new();
    for (index, line) in lines.iter().enumerate() {
        let Some(captures) = mrs.captures(line) else {
            continue;
        };
        let register = captures[1].to_string();
        let mut offsets: BTreeSet<u32> = BTreeSet::new();
        for next in &lines[index + 1..(index + 24).min(lines.len())] {
            let Some(entry) = load.captures(next) else {
                continue;
            };
            if &entry[1] != register.as_str() {
                continue;
            }
            if let Ok(offset) = u32::from_str_radix(&entry[2], 16) {
                offsets.insert(offset);
            }
        }
        for offset in &offsets {
            if offsets.contains(&(offset + 8)) {
                hits.insert(*offset);
            }
        }
    }
    unique_seccomp_offset(&hits)
}

fn unique_seccomp_offset(hits: &BTreeSet<u32>) -> Option<u32> {
    if hits.len() != 1 {
        return None;
    }
    let offset = *hits.iter().next()?;
    ((0x400..=0xc00).contains(&offset) && offset % 8 == 0).then_some(offset)
}

/// The `seccomp` field anchor: `__secure_computing` (mode load) first,
/// `copy_seccomp` (struct copy) as the fallback. Every candidate function is
/// tried; the first unique anchor wins.
pub fn derive_seccomp_offset(
    kernel: &[u8],
    symbols: &RelSymbols,
    sorted_offsets: &[u64],
) -> Option<(u32, &'static str)> {
    for name in ["__secure_computing", "__seccomp_filter", "copy_seccomp"] {
        let Ok(lines) = disassemble_symbol(kernel, symbols, sorted_offsets, name, SECCOMP_CAP)
        else {
            continue;
        };
        if let Some(offset) = seccomp_mode_load(&lines) {
            return Some((offset, "seccomp:mode-load"));
        }
        if let Some(offset) = seccomp_struct_copy(&lines) {
            return Some((offset, "seccomp:struct-copy"));
        }
    }
    None
}

/// The 5.10 `task_struct` fields that close on this image.
pub fn derive_task_struct_5_10(
    kernel: &[u8],
    symbols: &RelSymbols,
    sorted_offsets: &[u64],
    init_task_off: u64,
    _init_task_va: u64,
    init_cred_va: u64,
    root_task_group_va: u64,
) -> DerivedStructs {
    let mut out = kernel
        .get(init_task_off as usize..(init_task_off as usize).saturating_add(INIT_TASK_SCAN))
        .map(|chunk| derive_from_init_task(chunk, init_cred_va, root_task_group_va))
        .unwrap_or_default();
    if let Ok(lines) = disassemble_symbol(
        kernel,
        symbols,
        sorted_offsets,
        "copy_process",
        COPY_PROCESS_CAP,
    ) {
        out.extend(derive_from_copy_process(&lines, init_task_off));
    }
    if let Some((offset, source)) = derive_seccomp_offset(kernel, symbols, sorted_offsets) {
        out.insert("task_seccomp", offset, source);
    }
    out
}

/// The 5.10 `cred` layout from `init_cred`: the capability run and the
/// reference pointers. `image_text_base` is the image's `_text` VA; image
/// pointers are rebased onto the native's `KIMAGE_TEXT_BASE` spelling.
pub fn derive_cred_layout_5_10(
    kernel: &[u8],
    init_cred_off: u64,
    image_text_base: u64,
) -> Option<Cred5x> {
    let size = CRED_COPY_SIZE as usize;
    let bytes = kernel.get(init_cred_off as usize..init_cred_off as usize + size)?;

    /* The caps are five 8-byte slots (`cap_inheritable` through
     * `cap_ambient`). The initial credential has the middle three set to the
     * full mask and the outer two zero, so a three-slot run with a zero slot
     * on each side closes the array at run_start - 8. */
    let mut best: Option<(usize, usize, u64)> = None;
    let mut cursor = 0usize;
    while cursor + 8 <= bytes.len() {
        let value = u64_at(bytes, cursor)?;
        if value == 0 {
            cursor += 8;
            continue;
        }
        let mut length = 1usize;
        let mut next = cursor + 8;
        while next + 8 <= bytes.len() && u64_at(bytes, next)? == value {
            length += 1;
            next += 8;
        }
        if length >= 3 && best.map_or(true, |(_, best_len, _)| length > best_len) {
            best = Some((cursor, length, value));
        }
        cursor = next;
    }
    let (run_start, run_len, caps_value) = best?;
    if caps_value & CAP_FULL_SET != CAP_FULL_SET {
        return None;
    }
    let caps_offset = match run_len {
        CAPS_SLOTS => run_start,
        3 | 4 if run_start >= 8 && u64_at(bytes, run_start - 8)? == 0 => run_start - 8,
        _ => return None,
    };
    if caps_offset + CAPS_SLOTS * 8 > bytes.len() {
        return None;
    }

    /* Reference pointers inside the credential object; the copy-size bound
     * excludes the neighbouring objects that follow init_cred. */
    let mut refs: Vec<(u32, u64)> = Vec::new();
    for offset in (0..bytes.len().saturating_sub(8)).step_by(8) {
        let value = u64_at(bytes, offset)?;
        if value >> 48 == 0xffff && value >= image_text_base {
            refs.push((
                offset as u32,
                KIMAGE_TEXT_BASE.checked_add(value - image_text_base)?,
            ));
        }
    }
    if refs.is_empty() || refs.len() > REF_LIMIT {
        return None;
    }
    Some(Cred5x {
        caps_offset: caps_offset as u32,
        caps_count: CAPS_SLOTS as u32,
        caps_value,
        refs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Diagnostic helper for the seccomp anchor: dumps the candidate symbols
    /// from one image. Run with
    /// `GHOSTLOCK_DUMP_IMAGE=<path> cargo test --lib dump_seccomp_symbols -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn dump_seccomp_symbols() {
        let path = std::env::var("GHOSTLOCK_DUMP_IMAGE").expect("GHOSTLOCK_DUMP_IMAGE");
        let boot = crate::boot::BootImage::load(std::path::Path::new(&path)).expect("load");
        let btf = boot.embedded_btf_at();
        let pair = btf.as_ref().map(|(offset, blob)| (*offset, blob.len()));
        let symbols = crate::kallsyms_finder::recover(&boot.kernel, pair)
            .expect("kallsyms")
            .symbols;
        let base = crate::kallsyms::unique(&symbols, "_text")
            .or_else(|| crate::kallsyms::unique(&symbols, "_head"))
            .expect("base");
        let (relative, sorted) = crate::derive::relative_symbols(&symbols, base);
        for name in ["__secure_computing", "__seccomp_filter", "copy_seccomp"] {
            match disassemble_symbol(&boot.kernel, &relative, &sorted, name, SECCOMP_CAP) {
                Ok(lines) => {
                    eprintln!("== {name}: {} lines", lines.len());
                    for line in lines.iter().take(140) {
                        eprintln!("{line}");
                    }
                }
                Err(err) => eprintln!("== {name}: {err}"),
            }
        }
    }

    #[test]
    fn init_task_data_anchors_close() {
        let init_cred = 0xffff_ffc0_0a7b_0a60u64;
        let root_group = 0xffff_ffc0_0a99_3040u64;
        let mut chunk = vec![0u8; 0x1000];
        chunk[0x40..0x48].copy_from_slice(b"swapper\0");
        chunk[0x50..0x58].copy_from_slice(&init_cred.to_le_bytes());
        chunk[0x58..0x60].copy_from_slice(&init_cred.to_le_bytes());
        chunk[0x60..0x68].copy_from_slice(&root_group.to_le_bytes());
        for offset in [0x70usize, 0x74, 0x78] {
            chunk[offset..offset + 4].copy_from_slice(&120u32.to_le_bytes());
        }

        let derived = derive_from_init_task(&chunk, init_cred, root_group);
        assert_eq!(derived.values.get("task_comm"), Some(&0x40));
        assert_eq!(derived.values.get("task_real_cred"), Some(&0x50));
        assert_eq!(derived.values.get("task_cred"), Some(&0x58));
        assert_eq!(derived.values.get("task_sched_task_group"), Some(&0x60));
        assert_eq!(derived.values.get("task_prio"), Some(&0x70));
        assert_eq!(derived.values.get("task_normal_prio"), Some(&0x78));
    }

    #[test]
    fn a_duplicate_anchor_is_not_guessed() {
        let init_cred = 0xffff_ffc0_0a7b_0a60u64;
        let mut chunk = vec![0u8; 0x1000];
        for offset in [0x50usize, 0x58, 0x100] {
            chunk[offset..offset + 8].copy_from_slice(&init_cred.to_le_bytes());
        }
        let derived = derive_from_init_task(&chunk, init_cred, 0);
        assert!(derived.values.get("task_cred").is_none());
        assert!(derived.values.get("task_real_cred").is_none());
    }

    #[test]
    fn copy_process_stores_close() {
        let lines: Vec<String> = [
            "ldr w8, [x8, #0x60]",
            "str w8, [x20, #0x5c8]",
            "ldr w8, [x19, #0x5cc]",
            "str w8, [x20, #0x5cc]",
            "str wzr, [x20, #0x86c]",
            "str xzr, [x20, #0x880]",
            "str xzr, [x20, #0x888]",
            "str xzr, [x20, #0x890]",
            "str xzr, [x20, #0x898]",
            "adrp x9, 0x279c000",
            "add x9, x9, #0x348",
            "add x1, x20, #0x4c8",
            "str x9, [x20, #0x4c8]",
        ]
        .iter()
        .map(|line| line.to_string())
        .collect();
        let derived = derive_from_copy_process(&lines, 0x279be80);
        assert_eq!(derived.values.get("task_pid"), Some(&0x5c8));
        assert_eq!(derived.values.get("task_tgid"), Some(&0x5cc));
        assert_eq!(derived.values.get("task_pi_lock"), Some(&0x86c));
        assert_eq!(derived.values.get("task_pi_waiters"), Some(&0x880));
        assert_eq!(derived.values.get("task_pi_top_task"), Some(&0x890));
        assert_eq!(derived.values.get("task_pi_blocked_on"), Some(&0x898));
        assert_eq!(derived.values.get("task_tasks"), Some(&0x4c8));
    }

    #[test]
    fn cred_layout_reads_caps_and_refs() {
        let text_base = 0xffff_ffc0_0800_0000u64;
        let mut bytes = vec![0u8; CRED_COPY_SIZE as usize];
        bytes[0..8].copy_from_slice(&4u64.to_le_bytes());
        for offset in [0x30usize, 0x38, 0x40] {
            bytes[offset..offset + 8].copy_from_slice(&CAP_FULL_SET.to_le_bytes());
        }
        for (offset, value) in [
            (0x80usize, text_base + 0x1000),
            (0x88, text_base + 0x2000),
            (0x90, text_base + 0x3000),
        ] {
            bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        /* Neighbouring data beyond the copy size must not be picked up. */
        let mut extended = bytes.clone();
        extended.extend_from_slice(&(text_base + 0x4000).to_le_bytes());
        assert_eq!(
            derive_cred_layout_5_10(&extended, 0, text_base),
            Some(Cred5x {
                caps_offset: 0x28,
                caps_count: 5,
                caps_value: CAP_FULL_SET,
                refs: vec![
                    (0x80, KIMAGE_TEXT_BASE + 0x1000),
                    (0x88, KIMAGE_TEXT_BASE + 0x2000),
                    (0x90, KIMAGE_TEXT_BASE + 0x3000),
                ],
            })
        );
    }
}
