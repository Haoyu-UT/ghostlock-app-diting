//! Android DTBO images and FDT `/memory` lookup: derive the DRAM base
//! (`kernel_phys_offset`) from a device tree blob, without root.
//!
//! Two containers occur in practice:
//! - `dtbo.img`: the Android `dt_table_header` format (`DT_TABLE_MAGIC`) with
//!   one or more DTBs at offsets from the table start.
//! - a vendor_boot `dtb` section: on MediaTek this is the *same* DTBO table
//!   format even though the header field is called `dtb_size`; a plain FDT is
//!   accepted as well.
//!
//! The DRAM base is the lowest `/memory` `reg` base in the blob. Every DTB in
//! a table must agree, so a multi-board table cannot silently pick one
//! variant's memory map.

use std::fs;
use std::path::Path;

use crate::error::{ExtractError, Result};
use crate::fdt::{FDT_BEGIN_NODE, FDT_END, FDT_END_NODE, FDT_MAGIC, FDT_NOP, FDT_PROP};

/// Android `dt_table_header.magic` (`dtbo.img`, and the vendor_boot dtb
/// section on MediaTek).
pub const DT_TABLE_MAGIC: u32 = 0xD7B7_AB1E;

const DT_TABLE_HEADER_SIZE: usize = 32;
const DT_TABLE_ENTRY_SIZE: usize = 32;
const FDT_HEADER_SIZE: usize = 40;
const MAX_ENTRY_COUNT: usize = 4096;
/// Refuse absurd section sizes instead of allocating them from a bad header.
pub const MAX_DTB_SECTION: u64 = 64 * 1024 * 1024;

fn rd_be_u32(data: &[u8], off: usize) -> Result<u32> {
    let end = off
        .checked_add(4)
        .filter(|end| *end <= data.len())
        .ok_or_else(|| ExtractError::new(format!("truncated DTB at offset {off}")))?;
    Ok(u32::from_be_bytes(data[off..end].try_into().unwrap()))
}

/// One DTB found in the blob.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DtbEntry<'a> {
    /// Entry index inside a DTBO table; `None` for a plain FDT.
    pub index: Option<usize>,
    pub data: &'a [u8],
}

/// Reads `dtbo.img` and returns the DRAM base named by its DTBs' `/memory`.
pub fn memory_base_from_path(path: &Path) -> Result<u64> {
    let size = fs::metadata(path)?.len();
    if size > MAX_DTB_SECTION {
        return Err(ExtractError::new(format!(
            "{} is {size} bytes, larger than any plausible DTBO image \
             (limit {MAX_DTB_SECTION})",
            path.display()
        )));
    }
    let data = fs::read(path)?;
    memory_base(&data)
}

/// The unique DRAM base in a DTBO image or a plain DTB.
///
/// DTBO entries without a `/memory` node (overlays) are ignored as long as one
/// entry resolves; two different bases are a conflict and are refused.
pub fn memory_base(blob: &[u8]) -> Result<u64> {
    let entries = dtb_entries(blob)?;
    let mut bases: Vec<u64> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    for entry in &entries {
        match dtb_memory_base(entry.data) {
            Ok(base) => bases.push(base),
            Err(err) => errors.push(match entry.index {
                Some(index) => format!("DTB entry {index}: {err}"),
                None => err.to_string(),
            }),
        }
    }
    bases.sort_unstable();
    bases.dedup();
    match bases.as_slice() {
        [base] => Ok(*base),
        // A real dtbo.img is a list of overlays; reporting every entry's
        // "no /memory" turns one diagnosis into 50 lines.
        [] => match errors.as_slice() {
            [] => Err(ExtractError::new(
                "no /memory node with a reg property in the DTB",
            )),
            [only] => Err(ExtractError::new(only.clone())),
            [first, rest @ ..] => Err(ExtractError::new(format!(
                "no /memory node with a reg property in the DTB \
                 ({} DTBO entries; first: {first}; {} more failed)",
                entries.len(),
                rest.len()
            ))),
        },
        _ => Err(ExtractError::new(format!(
            "conflicting /memory bases in the DTBO entries: {bases:x?}"
        ))),
    }
}

/// Splits a DTBO image (or a vendor_boot dtb section) into its DTBs.
pub fn dtb_entries(blob: &[u8]) -> Result<Vec<DtbEntry<'_>>> {
    match rd_be_u32(blob, 0)? {
        DT_TABLE_MAGIC => parse_dtbo_table(blob),
        FDT_MAGIC => Ok(vec![DtbEntry {
            index: None,
            data: blob,
        }]),
        magic => Err(ExtractError::new(format!(
            "neither a DTBO table nor an FDT (first word 0x{magic:08x})"
        ))),
    }
}

fn parse_dtbo_table(data: &[u8]) -> Result<Vec<DtbEntry<'_>>> {
    if data.len() < DT_TABLE_HEADER_SIZE {
        return Err(ExtractError::new("DTBO header is truncated"));
    }
    let total_size = rd_be_u32(data, 4)? as usize;
    let header_size = rd_be_u32(data, 8)? as usize;
    let entry_size = rd_be_u32(data, 12)? as usize;
    let entry_count = rd_be_u32(data, 16)? as usize;
    let entries_offset = rd_be_u32(data, 20)? as usize;

    if header_size < DT_TABLE_HEADER_SIZE {
        return Err(ExtractError::new(format!(
            "DTBO header_size={header_size} is below {DT_TABLE_HEADER_SIZE}"
        )));
    }
    if entry_size < DT_TABLE_ENTRY_SIZE {
        return Err(ExtractError::new(format!(
            "DTBO entry_size={entry_size} is below {DT_TABLE_ENTRY_SIZE}"
        )));
    }
    if entry_count > MAX_ENTRY_COUNT {
        return Err(ExtractError::new(format!(
            "DTBO entry_count={entry_count} exceeds {MAX_ENTRY_COUNT}"
        )));
    }
    if total_size < header_size || total_size > data.len() {
        return Err(ExtractError::new(format!(
            "DTBO total_size={total_size} does not fit the {} byte blob",
            data.len()
        )));
    }
    let entries_end = entries_offset
        .checked_add(
            entry_count
                .checked_mul(entry_size)
                .ok_or_else(|| ExtractError::new("DTBO entry table size overflows"))?,
        )
        .ok_or_else(|| ExtractError::new("DTBO entry table offset overflows"))?;
    if entries_offset < header_size || entries_end > total_size {
        return Err(ExtractError::new(format!(
            "DTBO entry table [{entries_offset}, {entries_end}) is outside \
             the {total_size} byte table"
        )));
    }

    let mut out = Vec::with_capacity(entry_count);
    for index in 0..entry_count {
        let entry = entries_offset + index * entry_size;
        let dtb_size = rd_be_u32(data, entry)? as usize;
        let dtb_offset = rd_be_u32(data, entry + 4)? as usize;
        if dtb_size == 0 {
            return Err(ExtractError::new(format!("DTBO entry {index} is empty")));
        }
        let dtb_end = dtb_offset
            .checked_add(dtb_size)
            .filter(|end| *end <= total_size)
            .ok_or_else(|| {
                ExtractError::new(format!(
                    "DTBO entry {index} [{dtb_offset}, +{dtb_size}) is outside \
                     the {total_size} byte table"
                ))
            })?;
        out.push(DtbEntry {
            index: Some(index),
            data: &data[dtb_offset..dtb_end],
        });
    }
    Ok(out)
}

/// The lowest `/memory` base declared by one FDT.
pub fn dtb_memory_base(dtb: &[u8]) -> Result<u64> {
    let header = FdtHeader::parse(dtb)?;
    let struct_end = header.off_struct + header.size_struct;
    let strings_end = header.off_strings + header.size_strings;

    struct Node {
        name: String,
        depth: usize,
        parent_ac: u32,
        parent_sc: u32,
        child_ac: u32,
        child_sc: u32,
        reg: Option<Vec<u8>>,
        is_memory: bool,
    }

    let mut stack: Vec<Node> = Vec::new();
    let mut bases: Vec<u64> = Vec::new();
    let mut pos = header.off_struct;
    let mut terminated = false;
    while pos + 4 <= struct_end {
        let token = rd_be_u32(dtb, pos)?;
        match token {
            FDT_BEGIN_NODE => {
                let name_start = pos + 4;
                let nul = dtb[name_start..struct_end]
                    .iter()
                    .position(|b| *b == 0)
                    .map(|i| name_start + i)
                    .ok_or_else(|| ExtractError::new("unterminated FDT node name"))?;
                let name = std::str::from_utf8(&dtb[name_start..nul])
                    .map_err(|_| ExtractError::new("non-ascii FDT node name"))?
                    .to_string();
                let (parent_ac, parent_sc) = match stack.last() {
                    Some(parent) => (parent.child_ac, parent.child_sc),
                    None => (2, 1),
                };
                let depth = stack.len();
                stack.push(Node {
                    name,
                    depth,
                    parent_ac,
                    parent_sc,
                    child_ac: 2,
                    child_sc: 1,
                    reg: None,
                    is_memory: false,
                });
                pos = align4(nul + 1);
            }
            FDT_END_NODE => {
                let node = stack
                    .pop()
                    .ok_or_else(|| ExtractError::new("FDT end-node without a node"))?;
                if node.depth == 1
                    && (node.is_memory || node.name == "memory" || node.name.starts_with("memory@"))
                {
                    if let Some(reg) = &node.reg {
                        bases.extend(reg_bases(reg, node.parent_ac, node.parent_sc)?);
                    }
                }
                pos += 4;
            }
            FDT_PROP => {
                let size = rd_be_u32(dtb, pos + 4)? as usize;
                let name_off = rd_be_u32(dtb, pos + 8)? as usize;
                let value_start = pos + 12;
                let value_end = value_start
                    .checked_add(size)
                    .filter(|end| *end <= struct_end)
                    .ok_or_else(|| ExtractError::new("FDT property runs past the struct block"))?;
                let name_pos = header.off_strings + name_off;
                if name_off >= header.size_strings || name_pos >= strings_end {
                    return Err(ExtractError::new(
                        "FDT property name is outside the strings block",
                    ));
                }
                let name_end = dtb[name_pos..strings_end]
                    .iter()
                    .position(|b| *b == 0)
                    .map(|i| name_pos + i)
                    .ok_or_else(|| ExtractError::new("unterminated FDT property name"))?;
                let name = std::str::from_utf8(&dtb[name_pos..name_end])
                    .map_err(|_| ExtractError::new("non-ascii FDT property name"))?;
                let node = stack
                    .last_mut()
                    .ok_or_else(|| ExtractError::new("FDT property outside a node"))?;
                match name {
                    "#address-cells" if size == 4 => {
                        node.child_ac = rd_be_u32(dtb, value_start)?;
                    }
                    "#size-cells" if size == 4 => {
                        node.child_sc = rd_be_u32(dtb, value_start)?;
                    }
                    "reg" => node.reg = Some(dtb[value_start..value_end].to_vec()),
                    "device_type" => {
                        node.is_memory = dtb[value_start..value_end]
                            .strip_suffix(b"\0")
                            .unwrap_or(&dtb[value_start..value_end])
                            == b"memory";
                    }
                    _ => {}
                }
                pos = align4(value_end);
            }
            FDT_NOP => pos += 4,
            FDT_END => {
                terminated = true;
                break;
            }
            other => {
                return Err(ExtractError::new(format!(
                    "unknown FDT token 0x{other:08x} at offset {pos}"
                )));
            }
        }
    }
    if !terminated {
        return Err(ExtractError::new("truncated FDT: no end token"));
    }
    bases
        .into_iter()
        .min()
        .ok_or_else(|| ExtractError::new("no /memory node with a reg property in the DTB"))
}

struct FdtHeader {
    off_struct: usize,
    size_struct: usize,
    off_strings: usize,
    size_strings: usize,
}

impl FdtHeader {
    fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < FDT_HEADER_SIZE {
            return Err(ExtractError::new("FDT header is truncated"));
        }
        if rd_be_u32(data, 0)? != FDT_MAGIC {
            return Err(ExtractError::new("not an FDT (missing d00dfeed magic)"));
        }
        let total = rd_be_u32(data, 4)? as usize;
        let off_struct = rd_be_u32(data, 8)? as usize;
        let off_strings = rd_be_u32(data, 12)? as usize;
        let version = rd_be_u32(data, 20)?;
        let last_comp_version = rd_be_u32(data, 24)?;
        let size_strings = rd_be_u32(data, 32)? as usize;
        let size_struct = rd_be_u32(data, 36)? as usize;
        if version < 16 || last_comp_version > 17 {
            return Err(ExtractError::new(format!(
                "unsupported FDT version {version}/{last_comp_version}"
            )));
        }
        if total < FDT_HEADER_SIZE || total > data.len() {
            return Err(ExtractError::new(format!(
                "FDT totalsize={total} does not fit the {} byte blob",
                data.len()
            )));
        }
        if off_struct > total || size_struct > total - off_struct {
            return Err(ExtractError::new("FDT struct block is out of bounds"));
        }
        if off_strings > total || size_strings > total - off_strings {
            return Err(ExtractError::new("FDT strings block is out of bounds"));
        }
        Ok(Self {
            off_struct,
            size_struct,
            off_strings,
            size_strings,
        })
    }
}

/// Converts one `reg` entry list into the base of every non-empty region.
fn reg_bases(reg: &[u8], address_cells: u32, size_cells: u32) -> Result<Vec<u64>> {
    if !(1..=2).contains(&address_cells) || !(1..=2).contains(&size_cells) {
        return Err(ExtractError::new(format!(
            "unsupported /memory cells (#address-cells={address_cells}, \
             #size-cells={size_cells})"
        )));
    }
    let cells = (address_cells + size_cells) as usize;
    if reg.is_empty() || reg.len() % (cells * 4) != 0 {
        return Err(ExtractError::new(format!(
            "/memory reg length {} is not a multiple of {cells} cells",
            reg.len()
        )));
    }
    let address_bytes = address_cells as usize * 4;
    let mut bases = Vec::new();
    for entry in reg.chunks_exact(cells * 4) {
        let base = read_cells(&entry[..address_bytes]);
        let size = read_cells(&entry[address_bytes..]);
        if size != 0 {
            bases.push(base);
        }
    }
    Ok(bases)
}

fn read_cells(cells: &[u8]) -> u64 {
    match cells.len() {
        4 => u32::from_be_bytes(cells.try_into().unwrap()) as u64,
        8 => u64::from_be_bytes(cells.try_into().unwrap()),
        _ => 0,
    }
}

fn align4(value: usize) -> usize {
    (value + 3) & !3
}

#[cfg(test)]
pub(crate) mod testutil {
    use std::collections::HashMap;

    pub(crate) const MEMORY_BASE: u64 = 0x4000_0000;
    pub(crate) const MEMORY_SIZE: u64 = 0x3e60_5000;

    /// Builds a minimal valid FDT with a root node and one `memory` node.
    pub(crate) fn build_fdt(regions: &[(u64, u64)]) -> Vec<u8> {
        let mut builder = FdtBuilder::default();
        builder.begin("");
        builder.prop_cells("#address-cells", &[2]);
        builder.prop_cells("#size-cells", &[2]);
        builder.begin("memory");
        builder.prop("device_type", b"memory\0");
        let mut reg = Vec::new();
        for (base, size) in regions {
            reg.extend_from_slice(&base.to_be_bytes());
            reg.extend_from_slice(&size.to_be_bytes());
        }
        builder.prop("reg", &reg);
        builder.end();
        builder.end();
        builder.finish()
    }

    /// Wraps DTBs in the Android DTBO table format (`dtbo.img` / vendor_boot).
    pub(crate) fn build_dtbo(dtbs: &[Vec<u8>]) -> Vec<u8> {
        const HEADER: usize = 32;
        const ENTRY: usize = 32;
        let entries_end = HEADER + ENTRY * dtbs.len();
        let mut offsets = Vec::new();
        let mut cursor = entries_end;
        for dtb in dtbs {
            offsets.push(cursor);
            cursor += dtb.len();
        }
        let total = cursor;
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&0xD7B7_AB1Eu32.to_be_bytes());
        out.extend_from_slice(&(total as u32).to_be_bytes());
        out.extend_from_slice(&(HEADER as u32).to_be_bytes());
        out.extend_from_slice(&(ENTRY as u32).to_be_bytes());
        out.extend_from_slice(&(dtbs.len() as u32).to_be_bytes());
        out.extend_from_slice(&(HEADER as u32).to_be_bytes());
        out.extend_from_slice(&4096u32.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        for (dtb, offset) in dtbs.iter().zip(&offsets) {
            out.extend_from_slice(&(dtb.len() as u32).to_be_bytes());
            out.extend_from_slice(&(*offset as u32).to_be_bytes());
            out.extend_from_slice(&[0u8; ENTRY - 8]);
        }
        for dtb in dtbs {
            out.extend_from_slice(dtb);
        }
        out
    }

    #[derive(Default)]
    struct FdtBuilder {
        structs: Vec<u8>,
        strings: Vec<u8>,
        names: HashMap<String, usize>,
    }

    impl FdtBuilder {
        fn begin(&mut self, name: &str) {
            self.structs.extend_from_slice(&1u32.to_be_bytes());
            self.structs.extend_from_slice(name.as_bytes());
            self.structs.push(0);
            while self.structs.len() % 4 != 0 {
                self.structs.push(0);
            }
        }

        fn end(&mut self) {
            self.structs.extend_from_slice(&2u32.to_be_bytes());
        }

        fn prop(&mut self, name: &str, value: &[u8]) {
            let name_off = match self.names.get(name) {
                Some(off) => *off,
                None => {
                    let off = self.strings.len();
                    self.strings.extend_from_slice(name.as_bytes());
                    self.strings.push(0);
                    self.names.insert(name.to_string(), off);
                    off
                }
            };
            self.structs.extend_from_slice(&3u32.to_be_bytes());
            self.structs
                .extend_from_slice(&(value.len() as u32).to_be_bytes());
            self.structs
                .extend_from_slice(&(name_off as u32).to_be_bytes());
            self.structs.extend_from_slice(value);
            while self.structs.len() % 4 != 0 {
                self.structs.push(0);
            }
        }

        fn prop_cells(&mut self, name: &str, cells: &[u32]) {
            let mut value = Vec::new();
            for cell in cells {
                value.extend_from_slice(&cell.to_be_bytes());
            }
            self.prop(name, &value);
        }

        fn finish(mut self) -> Vec<u8> {
            self.structs.extend_from_slice(&9u32.to_be_bytes()); // FDT_END
            let off_rsvmap = 40usize;
            let off_struct = off_rsvmap + 16; // one empty rsvmap entry
            let off_strings = off_struct + self.structs.len();
            let total = off_strings + self.strings.len();
            let mut out = Vec::with_capacity(total);
            out.extend_from_slice(&0xD00D_FEEDu32.to_be_bytes());
            out.extend_from_slice(&(total as u32).to_be_bytes());
            out.extend_from_slice(&(off_struct as u32).to_be_bytes());
            out.extend_from_slice(&(off_strings as u32).to_be_bytes());
            out.extend_from_slice(&(off_rsvmap as u32).to_be_bytes());
            out.extend_from_slice(&17u32.to_be_bytes());
            out.extend_from_slice(&16u32.to_be_bytes());
            out.extend_from_slice(&0u32.to_be_bytes());
            out.extend_from_slice(&(self.strings.len() as u32).to_be_bytes());
            out.extend_from_slice(&(self.structs.len() as u32).to_be_bytes());
            out.extend_from_slice(&[0u8; 16]);
            out.extend_from_slice(&self.structs);
            out.extend_from_slice(&self.strings);
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::{MEMORY_BASE, MEMORY_SIZE, build_dtbo, build_fdt};
    use super::*;

    #[test]
    fn plain_fdt_memory_node_names_the_dram_base() {
        let dtb = build_fdt(&[(MEMORY_BASE, MEMORY_SIZE)]);
        assert_eq!(dtb_memory_base(&dtb).unwrap(), MEMORY_BASE);
        assert_eq!(memory_base(&dtb).unwrap(), MEMORY_BASE);
    }

    #[test]
    fn dtbo_table_entry_names_the_dram_base() {
        let blob = build_dtbo(&[build_fdt(&[(MEMORY_BASE, MEMORY_SIZE)])]);
        assert_eq!(memory_base(&blob).unwrap(), MEMORY_BASE);
    }

    #[test]
    fn the_lowest_memory_region_wins() {
        let dtb = build_fdt(&[(0x8000_0000, 0x1000_0000), (MEMORY_BASE, MEMORY_SIZE)]);
        assert_eq!(dtb_memory_base(&dtb).unwrap(), MEMORY_BASE);
    }

    #[test]
    fn trailing_padding_is_tolerated() {
        // dtbo.img is padded to its page size; total_size still excludes it.
        let mut blob = build_dtbo(&[build_fdt(&[(MEMORY_BASE, MEMORY_SIZE)])]);
        blob.resize(blob.len() + 4096, 0);
        assert_eq!(memory_base(&blob).unwrap(), MEMORY_BASE);
    }

    #[test]
    fn overlay_entries_without_memory_are_ignored() {
        let overlay = build_fdt(&[]); // a DTB without /memory
        let blob = build_dtbo(&[overlay, build_fdt(&[(MEMORY_BASE, MEMORY_SIZE)])]);
        assert_eq!(memory_base(&blob).unwrap(), MEMORY_BASE);
    }

    #[test]
    fn conflicting_bases_are_refused() {
        let blob = build_dtbo(&[
            build_fdt(&[(MEMORY_BASE, MEMORY_SIZE)]),
            build_fdt(&[(0x8000_0000, 0x1000_0000)]),
        ]);
        let err = memory_base(&blob).unwrap_err().to_string();
        assert!(err.contains("conflicting"), "{err}");
    }

    #[test]
    fn no_memory_node_is_refused() {
        let dtb = build_fdt(&[]);
        let err = dtb_memory_base(&dtb).unwrap_err().to_string();
        assert!(err.contains("/memory"), "{err}");
    }

    #[test]
    fn a_plain_fdt_is_not_a_dtbo_table() {
        let dtb = build_fdt(&[(MEMORY_BASE, MEMORY_SIZE)]);
        let entries = dtb_entries(&dtb).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].index, None);
    }

    #[test]
    fn dtbo_entry_offsets_are_relative_to_the_table() {
        let dtb = build_fdt(&[(MEMORY_BASE, MEMORY_SIZE)]);
        let blob = build_dtbo(&[dtb.clone()]);
        let entries = dtb_entries(&blob).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].index, Some(0));
        assert_eq!(entries[0].data, dtb.as_slice());
    }

    #[test]
    fn unknown_magic_is_refused() {
        let err = dtb_entries(b"ANDROID!\0\0\0\0").unwrap_err().to_string();
        assert!(err.contains("neither"), "{err}");
    }

    #[test]
    fn truncated_dtbo_table_is_refused() {
        let mut blob = build_dtbo(&[build_fdt(&[(MEMORY_BASE, MEMORY_SIZE)])]);
        blob.truncate(48);
        let err = memory_base(&blob).unwrap_err().to_string();
        assert!(
            err.contains("outside") || err.contains("total_size"),
            "{err}"
        );
    }
}
