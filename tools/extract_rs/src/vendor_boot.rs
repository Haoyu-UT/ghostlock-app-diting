//! `vendor_boot.img` parsing (MediaTek only): recover `kernel_phys_load` /
//! `kernel_phys_offset` without root, from the stock image alone.
//!
//! The header's `kernel_addr` is the kernel physical load. The DRAM base comes
//! from the DTB the image carries in its `dtb` section: on MediaTek that
//! section is a DTBO table (the same `DT_TABLE_MAGIC` format as `dtbo.img`),
//! although the header field is called `dtb_size`; a plain FDT is accepted too.
//! Without a usable DTB, the old alignment heuristic is the fallback and can
//! only *prove* the offset for the `text_offset` pattern (low 20 bits
//! `0x80000`).
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use crate::dtbo;
use crate::error::{ExtractError, Result};

const VNDRBOOT_MAGIC: &[u8; 8] = b"VNDRBOOT";

// No 32 Bit support, Just use 64 Bit text align
const ARM64_TEXT_ALIGN: u64 = 0x8_0000; // 512 KiB

/// The vendor_boot header prefix this parser reads (through `dtb_addr`).
const HEADER_PREFIX_SIZE: usize = 2112;
/// v4 grows the header to 2128 bytes (`vendor_ramdisk_table_*`, `bootconfig`).
const MIN_HEADER_SIZE: u32 = 2112;
const MAX_PAGE_SIZE: u32 = 1 << 20;

/// Where `phys_offset` came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhysOffsetSource {
    /// The embedded DTB's `/memory` node.
    EmbeddedDtb,
    /// The `kernel_addr` text-align pattern (`kernel_addr & 0xfffff == 0x80000`).
    HeaderAlignment,
    /// No source could prove it.
    Unset,
}

/// Everything the vendor_boot contributes to the profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VendorBootPhys {
    /// `kernel_addr`: the kernel's physical load address.
    pub kernel_addr: u64,
    pub phys_offset: Option<u64>,
    pub source: PhysOffsetSource,
    /// True when the header declares a `dtb` section (`dtb_size > 0`).
    pub has_dtb: bool,
    /// Why the embedded DTB could not be used, when it was present but failed.
    pub dtb_error: Option<String>,
    /// The offset the text-align pattern proves, when it proves one.
    pub header_offset: Option<u64>,
}

struct VendorBootHeader {
    page_size: u32,
    kernel_addr: u64,
    vendor_ramdisk_size: u64,
    dtb_size: u32,
}

/// Reads `vendor_boot.img` and derives the physical pair.
///
/// Only the header page and the `dtb` section are read, so a 128 MiB image
/// costs no more than its 331 KiB DTB.
pub fn recover_kernel_phys_from_vendor_boot(path: &Path) -> Result<VendorBootPhys> {
    let mut file = File::open(path)?;
    let file_len = file.metadata()?.len();
    let mut prefix = [0u8; HEADER_PREFIX_SIZE];
    file.read_exact(&mut prefix).map_err(|_| {
        ExtractError::new(format!(
            "{} is shorter than the {HEADER_PREFIX_SIZE}-byte vendor_boot header",
            path.display()
        ))
    })?;
    let header = parse_header(&prefix)?;
    if header.dtb_size == 0 {
        return resolve(&header, None);
    }

    let offset = dtb_section_offset(&header)?;
    let end = offset
        .checked_add(u64::from(header.dtb_size))
        .ok_or_else(|| ExtractError::new("vendor_boot dtb section overflows"))?;
    if end > file_len {
        return Err(ExtractError::new(format!(
            "vendor_boot dtb section [{offset}, {end}) is beyond the {file_len} byte image"
        )));
    }
    let mut dtb = vec![0u8; header.dtb_size as usize];
    file.seek(SeekFrom::Start(offset))?;
    file.read_exact(&mut dtb)?;
    resolve(&header, Some(&dtb))
}

/// Derives the physical pair from an in-memory vendor_boot image.
///
/// `data` must contain the whole image (the header and the dtb section).
pub fn parse_vendor_boot(data: &[u8]) -> Result<VendorBootPhys> {
    let header = parse_header(data)?;
    if header.dtb_size == 0 {
        return resolve(&header, None);
    }
    let offset = dtb_section_offset(&header)?;
    let end = offset
        .checked_add(u64::from(header.dtb_size))
        .ok_or_else(|| ExtractError::new("vendor_boot dtb section overflows"))?;
    if end > data.len() as u64 {
        return Err(ExtractError::new(format!(
            "vendor_boot dtb section [{offset}, {end}) is beyond the {} byte image",
            data.len()
        )));
    }
    let (start, end) = (offset as usize, end as usize);
    resolve(&header, Some(&data[start..end]))
}

/// Layout (`vendor_boot_img_hdr_v3/v4` common prefix, little-endian):
/// `magic[8] header_version[4] page_size[4] kernel_addr[4] ramdisk_addr[4]
/// vendor_ramdisk_size[4] cmdline[2048] tags_addr[4] name[16] header_size[4]
/// dtb_size[4] dtb_addr[8]`.
fn parse_header(data: &[u8]) -> Result<VendorBootHeader> {
    if data.len() < HEADER_PREFIX_SIZE {
        return Err(ExtractError::new(format!(
            "vendor_boot header is truncated ({} < {HEADER_PREFIX_SIZE} bytes)",
            data.len()
        )));
    }
    if &data[0..8] != VNDRBOOT_MAGIC {
        return Err(ExtractError::new(
            "not a vendor_boot.img (missing VNDRBOOT magic)",
        ));
    }
    let rd_u32 = |off: usize| u32::from_le_bytes(data[off..off + 4].try_into().unwrap());
    let header_version = rd_u32(8);
    if header_version < 3 {
        return Err(ExtractError::new(format!(
            "unexpected vendor_boot header_version={header_version} (expected >= 3)"
        )));
    }
    let page_size = rd_u32(12);
    if !page_size.is_power_of_two() || page_size > MAX_PAGE_SIZE {
        return Err(ExtractError::new(format!(
            "vendor_boot page_size={page_size} is not a plausible page size"
        )));
    }
    let header_size = rd_u32(2096);
    if header_size < MIN_HEADER_SIZE || header_size > page_size {
        return Err(ExtractError::new(format!(
            "vendor_boot header_size={header_size} does not fit page_size={page_size}"
        )));
    }
    let dtb_size = rd_u32(2100);
    if u64::from(dtb_size) > dtbo::MAX_DTB_SECTION {
        return Err(ExtractError::new(format!(
            "vendor_boot dtb_size={dtb_size} exceeds the {} byte limit",
            dtbo::MAX_DTB_SECTION
        )));
    }
    Ok(VendorBootHeader {
        page_size,
        kernel_addr: u64::from(rd_u32(16)),
        vendor_ramdisk_size: u64::from(rd_u32(24)),
        dtb_size,
    })
}

/// The dtb section starts on the next page after the vendor ramdisk.
fn dtb_section_offset(header: &VendorBootHeader) -> Result<u64> {
    let page = u64::from(header.page_size);
    let end = page
        .checked_add(header.vendor_ramdisk_size)
        .ok_or_else(|| ExtractError::new("vendor_boot ramdisk size overflows"))?;
    Ok((end + page - 1) & !(page - 1))
}

fn resolve(header: &VendorBootHeader, dtb: Option<&[u8]>) -> Result<VendorBootPhys> {
    let mut phys_offset = None;
    let mut source = PhysOffsetSource::Unset;
    let mut dtb_error = None;
    if let Some(blob) = dtb {
        match dtbo::memory_base(blob) {
            Ok(base) => {
                phys_offset = Some(base);
                source = PhysOffsetSource::EmbeddedDtb;
            }
            Err(err) => dtb_error = Some(err.to_string()),
        }
    }

    // The pattern check also identifies a MediaTek vendor_boot: `kernel_addr`
    // is an absolute physical load there, while the Qualcomm samples we have
    // carry a small relative offset (0x8000). An embedded DTB must not make
    // such an image look accepted.
    let header_offset = match header_phys_offset(header.kernel_addr) {
        Ok(offset) => offset,
        Err(err) => {
            return Err(match dtb_error {
                Some(dtb) => ExtractError::new(format!("{dtb}; {err}")),
                None => err,
            });
        }
    };
    if phys_offset.is_none() {
        match header_offset {
            Some(offset) => {
                phys_offset = Some(offset);
                source = PhysOffsetSource::HeaderAlignment;
            }
            // `kernel_addr` is MiB-aligned: consistent with the DRAM base, but
            // equally with a kernel loaded a whole number of MiB above it.
            None => source = PhysOffsetSource::Unset,
        }
    }

    Ok(VendorBootPhys {
        kernel_addr: header.kernel_addr,
        phys_offset,
        source,
        has_dtb: header.dtb_size > 0,
        dtb_error,
        header_offset,
    })
}

/// `kernel_addr` alone can prove the DRAM base only for the ARM64 text-align
/// pattern:
/// - `low == ARM64_TEXT_ALIGN` unambiguously means `phys_load = dram_base +
///   ARM64_TEXT_ALIGN`, so `phys_offset = phys_load - ARM64_TEXT_ALIGN`.
/// - `low == 0` only tells us `phys_load` is MiB-aligned. That is true both
///   when `phys_load == dram_base` *and* when the kernel is loaded a whole
///   number of MiB above the base (e.g. `phys_load=0x40200000` above
///   `dram_base=0x40000000`). Without a second, independent source we cannot
///   tell those apart, so the offset stays unset instead of guessing.
/// - anything else matches neither known update-package behaviour; refuse.
///
/// The last rule is also the MediaTek platform check: Qualcomm vendor_boots
/// carry a small relative `kernel_addr` (0x8000 in every sample on disk).
fn header_phys_offset(phys_load: u64) -> Result<Option<u64>> {
    let low = phys_load & 0xF_FFFF;
    if low == ARM64_TEXT_ALIGN {
        Ok(Some(phys_load - ARM64_TEXT_ALIGN))
    } else if low == 0 {
        Ok(None)
    } else {
        Err(ExtractError::new(format!(
            "kernel_phys_load=0x{phys_load:x} matches neither known MediaTek \
             alignment pattern (low 20 bits=0x{low:05x}); refusing to guess \
             kernel_phys_offset"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dtbo::testutil::{MEMORY_BASE, MEMORY_SIZE, build_dtbo, build_fdt};

    const PAGE: usize = 4096;

    /// Builds a vendor_boot image with `ramdisk_size` bytes of (uncompressed,
    /// unparseable) vendor ramdisk followed by an optional dtb section.
    fn vendor_boot(kernel_addr: u32, ramdisk_size: usize, dtb: Option<&[u8]>) -> Vec<u8> {
        let mut data = vec![0u8; PAGE];
        data[0..8].copy_from_slice(VNDRBOOT_MAGIC);
        data[8..12].copy_from_slice(&4u32.to_le_bytes()); // header_version
        data[12..16].copy_from_slice(&(PAGE as u32).to_le_bytes());
        data[16..20].copy_from_slice(&kernel_addr.to_le_bytes());
        data[20..24].copy_from_slice(&0x66f0_0000u32.to_le_bytes()); // ramdisk_addr
        data[24..28].copy_from_slice(&(ramdisk_size as u32).to_le_bytes());
        data[2076..2080].copy_from_slice(&0x47c8_0000u32.to_le_bytes()); // tags_addr
        data[2096..2100].copy_from_slice(&2128u32.to_le_bytes()); // header_size
        if let Some(dtb) = dtb {
            data[2100..2104].copy_from_slice(&(dtb.len() as u32).to_le_bytes());
            data[2104..2112].copy_from_slice(&0x47c8_0000u64.to_le_bytes()); // dtb_addr
        }
        data.resize(PAGE + ramdisk_size, 0xAA);
        while data.len() % PAGE != 0 {
            data.push(0);
        }
        if let Some(dtb) = dtb {
            data.extend_from_slice(dtb);
        }
        data
    }

    fn embedded_memory() -> Vec<u8> {
        build_dtbo(&[build_fdt(&[(MEMORY_BASE, MEMORY_SIZE)])])
    }

    #[test]
    fn embedded_dtbo_table_resolves_mib_aligned_load() {
        // The vivo PD2314 layout: kernel_addr=0x40000000 (MiB-aligned, so the
        // header pattern cannot prove anything), DTB in a DTBO table.
        let image = vendor_boot(0x4000_0000, 100, Some(&embedded_memory()));
        let phys = parse_vendor_boot(&image).unwrap();
        assert_eq!(phys.kernel_addr, 0x4000_0000);
        assert_eq!(phys.phys_offset, Some(MEMORY_BASE));
        assert_eq!(phys.source, PhysOffsetSource::EmbeddedDtb);
        assert!(phys.has_dtb);
        assert_eq!(phys.dtb_error, None);
        assert_eq!(phys.header_offset, None);
    }

    #[test]
    fn plain_embedded_fdt_is_accepted() {
        let dtb = build_fdt(&[(MEMORY_BASE, MEMORY_SIZE)]);
        let image = vendor_boot(0x4000_0000, 7, Some(&dtb));
        let phys = parse_vendor_boot(&image).unwrap();
        assert_eq!(phys.phys_offset, Some(MEMORY_BASE));
        assert_eq!(phys.source, PhysOffsetSource::EmbeddedDtb);
    }

    #[test]
    fn the_dtb_section_follows_the_page_aligned_ramdisk() {
        // 100 bytes of ramdisk do not fill a page; the DTB must still be found
        // at align(page_size + ramdisk_size, page_size).
        for ramdisk_size in [0usize, 1, 100, PAGE, PAGE + 1] {
            let image = vendor_boot(0x4000_0000, ramdisk_size, Some(&embedded_memory()));
            let phys = parse_vendor_boot(&image).unwrap();
            assert_eq!(
                phys.phys_offset,
                Some(MEMORY_BASE),
                "ramdisk_size={ramdisk_size}"
            );
        }
    }

    #[test]
    fn embedded_dtb_beats_the_header_alignment() {
        let image = vendor_boot(0x4008_0000, 0, Some(&embedded_memory()));
        let phys = parse_vendor_boot(&image).unwrap();
        assert_eq!(phys.phys_offset, Some(MEMORY_BASE));
        assert_eq!(phys.source, PhysOffsetSource::EmbeddedDtb);
        // Both sources agree here; the header pattern is still reported.
        assert_eq!(phys.header_offset, Some(MEMORY_BASE));
    }

    #[test]
    fn case_a_arm64_gki_alignment() {
        // Helio G81 Ultra: kernel_addr=0x40080000 proves
        // phys_offset=0x40000000 via the text-align pattern, no DTB needed.
        let image = vendor_boot(0x4008_0000, 0, None);
        let phys = parse_vendor_boot(&image).unwrap();
        assert_eq!(phys.kernel_addr, 0x4008_0000);
        assert_eq!(phys.phys_offset, Some(0x4000_0000));
        assert_eq!(phys.source, PhysOffsetSource::HeaderAlignment);
        assert!(!phys.has_dtb);
    }

    #[test]
    fn mib_aligned_load_does_not_imply_dram_base() {
        // kernel_addr=0x40000000 is consistent with dram_base=0x40000000
        // (Dimensity 6300), but equally with a kernel loaded a whole number of
        // MiB above a lower, unseen base. Without a DTB the pattern alone
        // cannot distinguish these, so phys_offset must stay unknown.
        let image = vendor_boot(0x4000_0000, 0, None);
        let phys = parse_vendor_boot(&image).unwrap();
        assert_eq!(phys.kernel_addr, 0x4000_0000);
        assert_eq!(phys.phys_offset, None);
        assert_eq!(phys.source, PhysOffsetSource::Unset);
    }

    #[test]
    fn mib_aligned_load_above_base_is_not_mistaken_for_it() {
        // A kernel loaded at 0x40200000 above a 0x40000000 base is also
        // MiB-aligned and must NOT yield phys_offset=0x40200000.
        let image = vendor_boot(0x4020_0000, 0, None);
        let phys = parse_vendor_boot(&image).unwrap();
        assert_eq!(phys.phys_offset, None);
    }

    #[test]
    fn unknown_alignment_is_refused_not_guessed() {
        let image = vendor_boot(0x4012_3456, 0, None);
        let err = parse_vendor_boot(&image).unwrap_err().to_string();
        assert!(err.contains("refusing to guess"), "{err}");
    }

    #[test]
    fn unparsable_dtb_falls_back_to_the_header_alignment() {
        let image = vendor_boot(0x4008_0000, 0, Some(b"not a dtb"));
        let phys = parse_vendor_boot(&image).unwrap();
        assert_eq!(phys.phys_offset, Some(0x4000_0000));
        assert_eq!(phys.source, PhysOffsetSource::HeaderAlignment);
        assert!(phys.dtb_error.is_some());
        assert!(phys.has_dtb);
    }

    #[test]
    fn unparsable_dtb_keeps_a_mib_aligned_load() {
        let image = vendor_boot(0x4000_0000, 0, Some(b"not a dtb"));
        let phys = parse_vendor_boot(&image).unwrap();
        assert_eq!(phys.kernel_addr, 0x4000_0000);
        assert_eq!(phys.phys_offset, None);
        assert_eq!(phys.source, PhysOffsetSource::Unset);
        assert!(phys.dtb_error.is_some());
    }

    #[test]
    fn a_dtb_does_not_mask_a_non_mediatek_kernel_addr() {
        // Every Qualcomm vendor_boot on disk carries kernel_addr=0x8000 (a
        // small relative offset, not an absolute load). Even if its DTB had a
        // /memory node, the image must not be accepted as MediaTek.
        let image = vendor_boot(0x8000, 100, Some(&embedded_memory()));
        let err = parse_vendor_boot(&image).unwrap_err().to_string();
        assert!(err.contains("refusing to guess"), "{err}");
    }

    #[test]
    fn dtb_section_beyond_the_image_is_refused() {
        // The header claims a 1 KiB dtb section but the image ends at the
        // page boundary; a truncated image is an error, not a silent fallback.
        let mut image = vendor_boot(0x4000_0000, 0, None);
        image[2100..2104].copy_from_slice(&1024u32.to_le_bytes());
        let err = parse_vendor_boot(&image).unwrap_err().to_string();
        assert!(err.contains("beyond"), "{err}");
    }

    #[test]
    fn wrong_magic_is_rejected() {
        let mut image = vendor_boot(0x4008_0000, 0, None);
        image[0..8].copy_from_slice(b"ANDROID!");
        let err = parse_vendor_boot(&image).unwrap_err().to_string();
        assert!(err.contains("VNDRBOOT"), "{err}");
    }

    #[test]
    fn old_header_version_is_rejected() {
        let mut image = vendor_boot(0x4008_0000, 0, None);
        image[8..12].copy_from_slice(&2u32.to_le_bytes()); // header_version < 3
        let err = parse_vendor_boot(&image).unwrap_err().to_string();
        assert!(err.contains("header_version"), "{err}");
    }

    #[test]
    fn inconsistent_header_size_is_rejected() {
        let mut image = vendor_boot(0x4008_0000, 0, None);
        image[2096..2100].copy_from_slice(&8192u32.to_le_bytes()); // > page_size
        let err = parse_vendor_boot(&image).unwrap_err().to_string();
        assert!(err.contains("header_size"), "{err}");
    }
}
