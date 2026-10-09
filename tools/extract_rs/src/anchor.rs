//! Derive `route.select_stack.lock_anchor_*` from a kernel image.
//!
//! The anchor is a zero, writable, reference-free region the PI walk uses as a
//! fake rt_mutex. Three numbers describe it, all per-build: the offset, how
//! many bytes of it are safe to use, and the distance between slots. Today they
//! are hand-picked with two throwaway examples plus human judgement, and the
//! length was wrong once already: the symbol *extent* is 0x1344, the array is
//! one page, and a rotation that trusted the extent walks into
//! `kernfs_pr_cont_buf`, a live printk buffer.
//!
//! The pivot here is that the derivable quantity is not a symbol size -- kallsyms
//! stores none -- but **the longest byte range starting at a candidate that
//! nothing live writes**. That is decidable, it subsumes the size question, and
//! it is self-correcting: extending past the page runs into a live store and
//! stops by construction, naming what stopped it.
//!
//! Design and its limits: docs/analysis/anchor-derivation-plan.md.

use std::collections::{BTreeMap, BTreeSet};

use yaxpeax_arch::{Decoder, Reader, U8Reader};
use yaxpeax_arm::armv8::a64::{InstDecoder, Operand, Opcode, SizeCode};

/// Image-relative section bounds the scan needs. Any of these may be absent on
/// an image that does not carry the symbol, in which case the caller should say
/// so rather than guess.
#[derive(Debug, Default, Clone, Copy)]
pub struct Bounds {
    pub text_start: u64,
    pub text_end: u64,
    /// Init text is freed after boot, so a reference from here executes only
    /// during bring-up. Not disqualifying, but it has to be reported: a store
    /// there leaves the region holding whatever boot left in it.
    pub init_start: u64,
    pub init_end: u64,
    pub bss_start: u64,
    pub bss_end: u64,
    /// Writable-from-boot boundary. A candidate before this is read-only after
    /// init and cannot be used at all.
    pub ro_after_init_end: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Read,
    Write,
}

#[derive(Debug, Clone)]
pub struct Reference {
    pub site: u64,
    pub target: u64,
    pub width: u8,
    pub kind: Kind,
    /// The site is inside init text.
    pub init: bool,
}

impl Reference {
    /// The byte range the access touches.
    pub fn range(&self) -> (u64, u64) {
        (self.target, self.target + self.width as u64)
    }
}

/// Decode the text section and return every direct reference into it.
///
/// "Direct" is the honest qualifier: this follows `adrp` + `add`/`ldr`/`str`,
/// which is how the kernel materialises the address of a .bss static. A store
/// through a pointer obtained some other way -- loaded from a table, built by
/// `movz`/`movk`, handed over by a caller -- is invisible here, which is why the
/// design also scans data sections for literals and why the verdict is
/// three-valued rather than a boolean.
pub fn scan_references(kernel: &[u8], bounds: &Bounds) -> Vec<Reference> {
    let mut refs = Vec::new();
    let start = bounds.text_start as usize;
    let end = bounds.text_end as usize;
    if end <= start || end > kernel.len() {
        return refs;
    }

    let decoder = InstDecoder::default();
    let mut reader = U8Reader::new(&kernel[start..end]);
    // Page base last materialised into each register by `adrp`. Cleared as soon
    // as the register is written by anything else, so a stale page can never be
    // attributed to an unrelated access.
    let mut page_of: [Option<u64>; 32] = [None; 32];

    loop {
        let pos = <U8Reader as Reader<u64, u8>>::total_offset(&mut reader) as usize;
        if pos >= end - start {
            break;
        }
        let addr = (start + pos) as u64;
        let Ok(insn) = decoder.decode(&mut reader) else {
            continue;
        };
        let ops = insn.operands;
        match insn.opcode {
            Opcode::ADRP => {
                if let (Operand::Register(_, rd), Operand::PCOffset(imm)) = (&ops[0], &ops[1]) {
                    // adrp target: (pc & !0xfff) + (imm << 12); yaxpeax renders
                    // PCOffset already page-shifted for adrp.
                    let base = (addr & !0xfff) as i64 + *imm;
                    page_of[*rd as usize % 32] = Some(base as u64);
                }
                continue;
            }
            Opcode::ADD => {
                // add Rd, Rn, #imm  ->  address of Rn's target + imm
                if let (Operand::Register(_, rd), Operand::Register(_, rn), Operand::Immediate(imm)) =
                    (&ops[0], &ops[1], &ops[2])
                {
                    if let Some(page) = page_of[*rn as usize % 32] {
                        let resolved = page.wrapping_add(*imm as u64);
                        page_of[*rd as usize % 32] = Some(resolved);
                        /* Not a reference on its own: it materialises an
                         * address, and whatever consumes it will be recorded
                         * when it does. */
                        let _ = resolved;
                        continue;
                    }
                }
                clear_dest(&ops, &mut page_of, false);
                continue;
            }
            Opcode::LDR | Opcode::LDRB | Opcode::LDRH | Opcode::LDRSW => {
                let width = reg_width(&ops[0]).unwrap_or(8);
                if let Some((page, off)) = base_plus_offset(&ops, &page_of) {
                    let target = page.wrapping_add(off);
                    /* The target is a data address, so it is NOT expected to be
                     * inside the text range -- an earlier version filtered on
                     * that and kept only the handful of references pointing back
                     * into text, which is the opposite of what is wanted. */
                    refs.push(Reference {
                        site: addr,
                        target,
                        width,
                        kind: Kind::Read,
                        init: in_init(addr, bounds),
                    });
                }
                if let Operand::Register(_, rd) = &ops[0] {
                    page_of[*rd as usize % 32] = None;
                }
                continue;
            }
            Opcode::STR | Opcode::STRB | Opcode::STRH => {
                let width = reg_width(&ops[0]).unwrap_or(8);
                if let Some((page, off)) = base_plus_offset(&ops, &page_of) {
                    let target = page.wrapping_add(off);
                    /* The target is a data address, so it is NOT expected to be
                     * inside the text range -- an earlier version filtered on
                     * that and kept only the handful of references pointing back
                     * into text, which is the opposite of what is wanted. */
                    refs.push(Reference {
                        site: addr,
                        target,
                        width,
                        kind: Kind::Write,
                        init: in_init(addr, bounds),
                    });
                }
                // A store's first operand is a source, not a destination.
                continue;
            }
            _ => {
                clear_dest(&ops, &mut page_of, false);
                continue;
            }
        }
    }
    refs
}

/// Access width implied by a register operand.
fn reg_width(op: &Operand) -> Option<u8> {
    match op {
        Operand::Register(code, _) => Some(size_of(*code)),
        _ => None,
    }
}

fn in_init(addr: u64, b: &Bounds) -> bool {
    b.init_end > b.init_start && addr >= b.init_start && addr < b.init_end
}

fn clear_dest(ops: &[Operand; 4], page_of: &mut [Option<u64>; 32], _keep: bool) {
    if let Operand::Register(_, rd) = &ops[0] {
        page_of[*rd as usize % 32] = None;
    }
}

/// `[Rn, #off]` with Rn carrying a page base. The immediate-offset form is
/// `RegPreIndex(reg, off, wback)` with the writeback bit clear; the
/// register-indexed forms have no constant offset and are not followed.
fn base_plus_offset(ops: &[Operand; 4], page_of: &[Option<u64>; 32]) -> Option<(u64, u64)> {
    for op in ops.iter() {
        if let Operand::RegPreIndex(rn, off, _) = op {
            if let Some(page) = page_of[*rn as usize % 32] {
                return Some((page, *off as i64 as u64));
            }
        }
    }
    None
}

/// A candidate region: a symbol inside writable .bss, with the extent kallsyms
/// implies (its distance to the next symbol -- an upper bound, not a size).
#[derive(Debug, Clone)]
pub struct Candidate {
    pub name: String,
    pub offset: u64,
    pub extent: u64,
}

pub fn candidates(
    rel: &BTreeMap<String, BTreeSet<u64>>,
    bounds: &Bounds,
    min_extent: u64,
) -> Vec<Candidate> {
    let mut all: Vec<(u64, String)> = Vec::new();
    for (name, offs) in rel {
        for o in offs {
            all.push((*o, name.clone()));
        }
    }
    all.sort();

    let mut out = Vec::new();
    for (i, (off, name)) in all.iter().enumerate() {
        if *off < bounds.bss_start || *off >= bounds.bss_end {
            continue;
        }
        if *off < bounds.ro_after_init_end {
            continue;
        }
        let next = all.get(i + 1).map(|(o, _)| *o).unwrap_or(bounds.bss_end);
        let extent = next.saturating_sub(*off);
        if extent < min_extent {
            continue;
        }
        out.push(Candidate {
            name: name.clone(),
            offset: *off,
            extent,
        });
    }
    out.sort_by(|a, b| b.extent.cmp(&a.extent));
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// No live references at all. The only verdict the tool accepts unaided.
    Safe,
    /// Live reads, or a literal pointer into the region. Benign or not is a
    /// judgement, and judgements get surfaced, not made.
    NeedsReview,
    /// A live write.
    Unsafe,
}

impl Verdict {
    pub fn label(self) -> &'static str {
        match self {
            Verdict::Safe => "safe",
            Verdict::NeedsReview => "needs-review",
            Verdict::Unsafe => "unsafe",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Assessment {
    pub candidate: Candidate,
    /// Longest prefix of the candidate that no live write touches and that does
    /// not run into another symbol carrying live references.
    pub safe_len: u64,
    /// What stopped the extension, in words, for the report.
    pub stopped_by: String,
    pub live_reads: Vec<Reference>,
    pub live_writes: Vec<Reference>,
    pub init_refs: Vec<Reference>,
    pub verdict: Verdict,
}

/// Extend from the candidate's start until something live stands in the way.
pub fn assess(
    cand: &Candidate,
    refs: &[Reference],
    rel: &BTreeMap<String, BTreeSet<u64>>,
    bounds: &Bounds,
) -> Assessment {
    let mut live_reads = Vec::new();
    let mut live_writes = Vec::new();
    let mut init_refs = Vec::new();
    for r in refs {
        if r.target < cand.offset || r.target >= cand.offset + cand.extent {
            continue;
        }
        if r.init {
            init_refs.push(r.clone());
        } else if r.kind == Kind::Write {
            live_writes.push(r.clone());
        } else {
            live_reads.push(r.clone());
        }
    }

    // Symbols that start after this one inside its extent: the first that
    // carries any live reference bounds the region, because past it we would be
    // sharing bytes with something the kernel is using.
    let mut blockers: Vec<(u64, String)> = Vec::new();
    for (name, offs) in rel {
        for o in offs {
            if *o > cand.offset && *o < cand.offset + cand.extent {
                let has_live = refs.iter().any(|r| {
                    !r.init && r.target >= *o && r.target < *o + 8
                });
                if has_live || live_writes.iter().any(|w| w.target >= *o) {
                    blockers.push((*o, name.clone()));
                }
            }
        }
    }
    blockers.sort();

    let write_limit = live_writes.iter().map(|w| w.target).min();
    let symbol_limit = blockers.first().map(|(o, _)| *o);
    let mut end = match (write_limit, symbol_limit) {
        (Some(w), Some(s)) => w.min(s),
        (Some(w), None) => w,
        (None, Some(s)) => s,
        (None, None) => cand.offset + cand.extent,
    };
    /* Past the end of .bss the bytes are no longer ours to assume zero, and
     * before `__end_ro_after_init` they are not writable at all. */
    if end > bounds.bss_end {
        end = bounds.bss_end;
    }
    if cand.offset < bounds.ro_after_init_end {
        end = cand.offset;
    }
    let safe_len = end.saturating_sub(cand.offset);

    let stopped_by = if let Some(w) = write_limit {
        if Some(w) == Some(end) {
            format!("live store at +0x{:x}", w)
        } else {
            format!("symbol {:?} at +0x{:x}", blockers[0].1, blockers[0].0)
        }
    } else if let Some((o, name)) = blockers.first() {
        format!("symbol {name:?} at +0x{o:x} carries live references")
    } else {
        "end of the candidate's extent".to_string()
    };

    let verdict = if !live_writes.is_empty() {
        Verdict::Unsafe
    } else if live_reads.is_empty() {
        Verdict::Safe
    } else {
        Verdict::NeedsReview
    };

    Assessment {
        candidate: cand.clone(),
        safe_len,
        stopped_by,
        live_reads,
        live_writes,
        init_refs,
        verdict,
    }
}

/// Register width in bytes -- which is also the access width for a load or a
/// store whose register form determines it.
pub fn size_of(code: SizeCode) -> u8 {
    match code {
        SizeCode::W => 4,
        SizeCode::X => 8,
    }
}
