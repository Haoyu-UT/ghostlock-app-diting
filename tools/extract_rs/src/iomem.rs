//! `/proc/iomem` parsing: derive the DRAM base (`kernel_phys_offset`) and, with
//! the kallsyms delta, the kernel physical load address. Used when the extractor
//! runs on a rooted device, or with an explicit `--iomem` dump.

use std::fs;
use std::path::Path;

use crate::error::Result;

const GIB_1: u64 = 0x4000_0000; // 1 GiB
const MIB_64: u64 = 0x0400_0000; // 64 MiB

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct IomemInfo {
    /// DRAM base / linear-map PHYS_OFFSET, or None when no System RAM is listed.
    pub dram_base: Option<u64>,
    /// Physical start of the `Kernel code` range (== `_stext` physical).
    pub kernel_code_start: Option<u64>,
}

fn parse_hex(text: &str) -> Option<u64> {
    u64::from_str_radix(text.trim(), 16).ok()
}

/// Parses an `/proc/iomem` dump. Lines look like `start-end : label`, possibly
/// indented for nested ranges.
pub fn parse(text: &str) -> IomemInfo {
    let mut regions: Vec<(u64, u64, String)> = Vec::new();
    for line in text.lines() {
        let Some((range, label)) = line.split_once(':') else {
            continue;
        };
        let Some((start_s, end_s)) = range.trim().split_once('-') else {
            continue;
        };
        if let (Some(start), Some(end)) = (parse_hex(start_s), parse_hex(end_s)) {
            regions.push((start, end, label.trim().to_string()));
        }
    }

    // DRAM base = the lowest "System RAM" start, lowered through an aligned
    // "reserved" carveout at the bottom of DRAM: some devices (Qualcomm) mark
    // the base reserved and may leave a small hole before the first System RAM.
    let mut base = regions
        .iter()
        .filter(|(_, _, label)| label.contains("System RAM"))
        .map(|(start, _, _)| *start)
        .min();
    if let Some(mut current) = base {
        loop {
            let mut changed = false;
            for (start, _end, label) in &regions {
                if label.contains("reserved")
                    && *start >= GIB_1
                    && *start < current
                    && current - *start <= MIB_64
                    && *start % MIB_64 == 0
                {
                    current = *start;
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
        base = Some(current);
    }

    let kernel_code_start = regions
        .iter()
        .find(|(_, _, label)| label.contains("Kernel code"))
        .map(|(start, _, _)| *start);

    IomemInfo {
        dram_base: base,
        kernel_code_start,
    }
}

/// True when a parsed dump carries usable physical addresses.
///
/// `/proc/iomem` is readable without `CAP_SYS_ADMIN` on a restricted kernel,
/// but the range starts are zeroed (`00000000-00000000 : Kernel code`). Using
/// that dump would write `kernel_phys_load = 0` and a zero DRAM base into the
/// profile, so it must fall through to the root child's cached dump.
fn usable(info: &IomemInfo) -> bool {
    match info.dram_base {
        Some(base) if base != 0 => info.kernel_code_start != Some(0),
        _ => false,
    }
}

/// Reads and parses `/proc/iomem`, or an explicit dump.
///
/// There is deliberately no cache: the only in-app dump would be written by the
/// native's root child after a successful run, and a successful run already
/// proves the base/offset were right — it cannot inform the first run. A fresh
/// device therefore gets `None`, the profile leaves the phys pair `null`, and
/// the native's compiled `P0_KERNEL_PHYS_LOAD` / `P0_PHYS_OFFSET` apply. A
/// rooted analysis context gets the real values from `/proc/iomem` or
/// `--iomem`; a dump with zeroed addresses is never used.
pub fn load(provided: Option<&Path>) -> Result<Option<IomemInfo>> {
    let (text, source) = match provided {
        Some(path) => {
            let text = fs::read_to_string(path).map_err(|err| {
                crate::error::ExtractError::new(format!(
                    "cannot read iomem {}: {err}",
                    path.display()
                ))
            })?;
            (text, path.display().to_string())
        }
        None => match fs::read_to_string("/proc/iomem") {
            Ok(text) => (text, "/proc/iomem".to_string()),
            Err(_) => return Ok(None),
        },
    };
    let info = parse(&text);
    if !usable(&info) {
        if info.dram_base.is_some() || info.kernel_code_start.is_some() {
            eprintln!(
                "warning: iomem {source} has no usable addresses; leaving the phys pair unset"
            );
        }
        return Ok(None);
    }
    if provided.is_none() {
        eprintln!("info: iomem source {source}");
    }
    Ok(Some(info))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dram_base_lowers_through_a_reserved_carveout() {
        // Qualcomm-style: reserved bottom, a small hole, then System RAM.
        let text = "\
00000000-00000fff : pci
80000000-80dfffff : reserved
811d0000-819fffff : System RAM
81a00000-81cf3fff : reserved
a2a80000-d4cfffff : System RAM
  a8010000-aa86ffff : Kernel code
";
        let info = parse(text);
        assert_eq!(info.dram_base, Some(0x8000_0000));
        assert_eq!(info.kernel_code_start, Some(0xa801_0000));
    }

    #[test]
    fn dram_base_is_the_first_system_ram_when_not_carved_out() {
        let text = "\
00000588-000005c3 : mt6359p-rtc
40000000-4807ffff : System RAM
  40090000-41d8ffff : Kernel code
";
        let info = parse(text);
        assert_eq!(info.dram_base, Some(0x4000_0000));
        assert_eq!(info.kernel_code_start, Some(0x4009_0000));
        assert!(usable(&info));
    }

    #[test]
    fn zeroed_addresses_are_not_usable() {
        // What an unprivileged `/proc/iomem` read looks like with
        // kptr_restrict=2: the ranges are present, their starts are zero.
        let text = "\
00000000-00000000 : System RAM
  00000000-00000000 : Kernel code
";
        let info = parse(text);
        assert_eq!(info.dram_base, Some(0));
        assert_eq!(info.kernel_code_start, Some(0));
        assert!(!usable(&info));
    }

    #[test]
    fn a_missing_kernel_code_range_still_has_a_usable_dram_base() {
        let info = parse("40000000-4807ffff : System RAM\n");
        assert!(usable(&info));
    }

}
