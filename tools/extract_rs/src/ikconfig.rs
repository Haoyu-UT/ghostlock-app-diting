//! Embedded kernel config (IKCONFIG) and the measured-series predicate.
//!
//! The extractor's shared template (`task_struct`, `cred` layout, the 5.10
//! waiter offsets) is frozen data measured on the diting
//! 5.10.236 build. Its scope is the series that produced the measurement, and
//! the series is decided from the image's own embedded config: the union of
//! every `CONFIG_*` guard inside `task_struct`, `cred`, `mm_struct` and
//! `rt_mutex_waiter` in the 5.10 tree, plus the preempt/UCLAMP/RANDSTRUCT
//! classes the template depends on. Any difference in that set is a series
//! mismatch (fail-closed).
//!
//! When the image carries no IKCONFIG, a patch-precise range of the measured
//! line is the lowest-priority fallback; every value it admits is a heuristic
//! and must be logged as such. The release suffix alone is never a series
//! source.

use std::collections::BTreeMap;
use std::io::Read;

use crate::error::{ExtractError, Result};

const START: &[u8] = b"IKCFG_ST";
const END: &[u8] = b"IKCFG_ED";

/// The measured 5.10.236 layout values. Sorted by option name; the order is
/// part of the fingerprint and must not be reshuffled without re-measuring.
pub const MEASURED_5_10_LAYOUT: &[(&str, &str)] = &[
    ("CONFIG_AIO", "y"),
    ("CONFIG_ARCH_HAS_SCALED_CPUTIME", "n"),
    ("CONFIG_ARCH_WANT_BATCHED_UNMAP_TLB_FLUSH", "n"),
    ("CONFIG_ARM64_VA_BITS", "39"),
    ("CONFIG_AUDIT", "y"),
    ("CONFIG_AUDITSYSCALL", "y"),
    ("CONFIG_BCACHE", "n"),
    ("CONFIG_BCACHE_MODULE", "n"),
    ("CONFIG_BLK_CGROUP", "y"),
    ("CONFIG_BLK_DEV_IO_TRACE", "n"),
    ("CONFIG_BLOCK", "y"),
    ("CONFIG_BPF_SYSCALL", "y"),
    ("CONFIG_CFI_CLANG", "y"),
    ("CONFIG_CGROUPS", "y"),
    ("CONFIG_CGROUP_BPF", "y"),
    ("CONFIG_CGROUP_SCHED", "y"),
    ("CONFIG_COMPACTION", "y"),
    ("CONFIG_COMPAT", "y"),
    ("CONFIG_COMPAT_BRK", "n"),
    ("CONFIG_CPUSETS", "y"),
    ("CONFIG_CPU_FREQ_TIMES", "y"),
    ("CONFIG_DEBUG_ATOMIC_SLEEP", "n"),
    ("CONFIG_DEBUG_CREDENTIALS", "n"),
    ("CONFIG_DEBUG_LOCK_ALLOC", "n"),
    ("CONFIG_DEBUG_MUTEXES", "n"),
    ("CONFIG_DEBUG_PREEMPT", "n"),
    ("CONFIG_DEBUG_RT_MUTEXES", "n"),
    ("CONFIG_DEBUG_SPINLOCK", "n"),
    ("CONFIG_DETECT_HUNG_TASK", "y"),
    ("CONFIG_FAIR_GROUP_SCHED", "y"),
    ("CONFIG_FAULT_INJECTION", "n"),
    ("CONFIG_FUNCTION_GRAPH_TRACER", "n"),
    ("CONFIG_FUTEX", "y"),
    ("CONFIG_GCC_PLUGIN_STACKLEAK", "n"),
    ("CONFIG_HAVE_ARCH_COMPAT_MMAP_BASES", "n"),
    ("CONFIG_HOTPLUG_CPU", "y"),
    ("CONFIG_HUGETLB_PAGE", "n"),
    ("CONFIG_HZ", "250"),
    ("CONFIG_IOMMU_SUPPORT", "y"),
    ("CONFIG_IO_URING", "y"),
    ("CONFIG_KASAN_GENERIC", "n"),
    ("CONFIG_KASAN_HW_TAGS", "y"),
    ("CONFIG_KASAN_SW_TAGS", "n"),
    ("CONFIG_KCOV", "n"),
    ("CONFIG_KCSAN", "n"),
    ("CONFIG_KEYS", "y"),
    ("CONFIG_KUNIT", "n"),
    ("CONFIG_LATENCYTOP", "n"),
    ("CONFIG_LIVEPATCH", "n"),
    ("CONFIG_LOCKDEP", "n"),
    ("CONFIG_MEMBARRIER", "y"),
    ("CONFIG_MEMCG", "y"),
    ("CONFIG_MMU", "y"),
    ("CONFIG_MMU_NOTIFIER", "y"),
    ("CONFIG_NO_HZ_FULL", "n"),
    ("CONFIG_NUMA", "n"),
    ("CONFIG_NUMA_BALANCING", "n"),
    ("CONFIG_PERF_EVENTS", "y"),
    ("CONFIG_POSIX_CPUTIMERS", "n"),
    ("CONFIG_POSIX_CPU_TIMERS_TASK_WORK", "n"),
    ("CONFIG_PREEMPT", "y"),
    ("CONFIG_PREEMPTION", "y"),
    ("CONFIG_PREEMPT_COUNT", "y"),
    ("CONFIG_PREEMPT_NOTIFIERS", "y"),
    ("CONFIG_PREEMPT_RCU", "y"),
    ("CONFIG_PREEMPT_RT", "n"),
    ("CONFIG_PSI", "y"),
    ("CONFIG_RANDSTRUCT", "n"),
    ("CONFIG_RSEQ", "n"),
    ("CONFIG_RT_GROUP_SCHED", "n"),
    ("CONFIG_RT_MUTEXES", "y"),
    ("CONFIG_SCHEDSTATS", "y"),
    ("CONFIG_SCHED_INFO", "y"),
    ("CONFIG_SECCOMP", "y"),
    ("CONFIG_SECCOMP_FILTER", "y"),
    ("CONFIG_SECURITY", "y"),
    ("CONFIG_SECURITY_SELINUX", "y"),
    ("CONFIG_SELINUX", "n"),
    ("CONFIG_SHADOW_CALL_STACK", "y"),
    ("CONFIG_SMP", "y"),
    ("CONFIG_SPECULATIVE_PAGE_FAULT", "y"),
    ("CONFIG_STACKPROTECTOR", "y"),
    ("CONFIG_STACKTRACE", "y"),
    ("CONFIG_SYSVIPC", "n"),
    ("CONFIG_TASKSTATS", "y"),
    ("CONFIG_TASKS_RCU", "y"),
    ("CONFIG_TASKS_TRACE_RCU", "y"),
    ("CONFIG_TASK_DELAY_ACCT", "y"),
    ("CONFIG_TASK_XACCT", "y"),
    ("CONFIG_THREAD_INFO_IN_TASK", "y"),
    ("CONFIG_TRACE_IRQFLAGS", "n"),
    ("CONFIG_TRACING", "y"),
    ("CONFIG_TRANSPARENT_HUGEPAGE", "y"),
    ("CONFIG_UBSAN", "y"),
    ("CONFIG_UBSAN_TRAP", "y"),
    ("CONFIG_UCLAMP_TASK", "y"),
    ("CONFIG_UCLAMP_TASK_GROUP", "y"),
    ("CONFIG_UPROBES", "y"),
    ("CONFIG_VIRT_CPU_ACCOUNTING_GEN", "n"),
    ("CONFIG_VMAP_STACK", "y"),
    ("CONFIG_X86_CPU_RESCTRL", "n"),
    ("CONFIG_X86_MCE", "n"),
];

/// The measured line's patch range, used only when the image has no IKCONFIG.
pub const MEASURED_5_10_PATCH_RANGE: (u32, u32) = (43, 246);

#[derive(Debug, Clone)]
pub struct KernelConfig {
    text: String,
    values: BTreeMap<String, String>,
}

impl KernelConfig {
    /// Extract and decompress the embedded `.config`. The blob is a gzip
    /// stream between `IKCFG_ST` and `IKCFG_ED`, emitted by
    /// `kernel/configs.c` when `CONFIG_IKCONFIG=y`.
    pub fn from_image(kernel: &[u8]) -> Result<Self> {
        let start = find(kernel, START)
            .ok_or_else(|| ExtractError::new("embedded IKCONFIG marker (IKCFG_ST) not found"))?;
        let window = &kernel[start + START.len()..];
        let gz = window
            .windows(2)
            .position(|pair| pair[0] == 0x1f && pair[1] == 0x8b)
            .filter(|offset| *offset < 64)
            .ok_or_else(|| ExtractError::new("IKCONFIG gzip magic not found after IKCFG_ST"))?;
        let body = &window[gz..];
        let end = find(body, END)
            .ok_or_else(|| ExtractError::new("IKCONFIG end marker (IKCFG_ED) not found"))?;
        let mut decoder = flate2::read::GzDecoder::new(&body[..end]);
        let mut text = String::new();
        decoder
            .read_to_string(&mut text)
            .map_err(|err| ExtractError::new(format!("IKCONFIG gzip decode failed: {err}")))?;
        let values = parse(&text);
        Ok(Self { text, values })
    }

    pub fn text(&self) -> &str {
        &self.text
    }

    pub fn value(&self, key: &str) -> &str {
        self.values.get(key).map(String::as_str).unwrap_or("n")
    }

    /// Options whose value differs from the measured 5.10.236 build. Empty
    /// means the image is in the measured series.
    pub fn layout_differences(&self) -> Vec<String> {
        MEASURED_5_10_LAYOUT
            .iter()
            .filter_map(|(key, expected)| {
                let actual = self.value(key);
                (actual != *expected).then(|| format!("{key}: measured={expected} image={actual}"))
            })
            .collect()
    }

    /// A stable hash of the image's layout options, in the measured table's
    /// order. FNV-1a is used because it is deterministic and dependency-free.
    pub fn layout_fingerprint(&self) -> String {
        let mut hash = 0xcbf2_9ce4_8422_2325u64;
        for (key, _) in MEASURED_5_10_LAYOUT {
            for byte in key
                .bytes()
                .chain(std::iter::once(b'='))
                .chain(self.value(key).bytes())
                .chain(std::iter::once(b'\n'))
            {
                hash ^= u64::from(byte);
                hash = hash.wrapping_mul(0x100_0000_01b3);
            }
        }
        format!("{hash:016x}")
    }

    /// A hash of the whole config, for provenance in the log.
    pub fn full_hash(&self) -> String {
        let mut hash = 0xcbf2_9ce4_8422_2325u64;
        for byte in self.text.bytes() {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x100_0000_01b3);
        }
        format!("{hash:016x}")
    }
}

/// How the image was placed in (or outside) the measured series.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeriesMatch {
    /// The embedded config's layout fingerprint matches the measured build.
    Fingerprint { fingerprint: String },
    /// No IKCONFIG; a patch-range fallback. Every template value it admits is
    /// a heuristic and must be labelled in the generation log.
    PatchRange { range: &'static str },
    /// Neither source matched: the template must not fill.
    None { reason: String },
}

impl SeriesMatch {
    pub fn matched(&self) -> bool {
        !matches!(self, SeriesMatch::None { .. })
    }

    pub fn is_heuristic(&self) -> bool {
        matches!(self, SeriesMatch::PatchRange { .. })
    }

    /// The series basis for the generation log.
    pub fn label(&self) -> String {
        match self {
            SeriesMatch::Fingerprint { fingerprint } => format!("ikconfig:{fingerprint}"),
            SeriesMatch::PatchRange { range } => {
                format!("patch-range:{range} (heuristic: no IKCONFIG)")
            }
            SeriesMatch::None { reason } => format!("none: {reason}"),
        }
    }
}

/// Decide the series for a 5.10 image. The IKCONFIG fingerprint is
/// authoritative; the patch range is used only when the blob is absent or
/// unparseable, and a fingerprint mismatch is final. Non-5.10 releases return
/// `None` (the template is 5.10-only).
pub fn series_5_10(config: Option<&KernelConfig>, release: &str) -> SeriesMatch {
    if !release.starts_with("5.10.") {
        return SeriesMatch::None {
            reason: "not a 5.10 release".to_string(),
        };
    }
    if let Some(config) = config {
        let differences = config.layout_differences();
        if differences.is_empty() {
            return SeriesMatch::Fingerprint {
                fingerprint: config.layout_fingerprint(),
            };
        }
        let shown = differences
            .iter()
            .take(6)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        let more = differences.len().saturating_sub(6);
        return SeriesMatch::None {
            reason: format!(
                "layout fingerprint mismatch ({} option(s) differ: {shown}{})",
                differences.len(),
                if more > 0 {
                    format!(", +{more} more")
                } else {
                    String::new()
                }
            ),
        };
    }
    let patch = release
        .split('.')
        .nth(2)
        .and_then(|part| part.split('-').next())
        .and_then(|part| part.parse::<u32>().ok());
    match patch {
        Some(patch) if (MEASURED_5_10_PATCH_RANGE.0..=MEASURED_5_10_PATCH_RANGE.1).contains(&patch) => {
            SeriesMatch::PatchRange {
                range: "5.10.43..=5.10.246",
            }
        }
        _ => SeriesMatch::None {
            reason: "no embedded IKCONFIG and the release is outside 5.10.43..=5.10.246"
                .to_string(),
        },
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn parse(text: &str) -> BTreeMap<String, String> {
    let mut values = BTreeMap::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("CONFIG_") {
            if let Some((key, value)) = rest.split_once('=') {
                values.insert(format!("CONFIG_{key}"), value.to_string());
            }
        } else if let Some(rest) = line.strip_prefix("# CONFIG_") {
            if let Some(key) = rest.strip_suffix(" is not set") {
                values.insert(format!("CONFIG_{key}"), "n".to_string());
            }
        }
    }
    values
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> KernelConfig {
        let text = MEASURED_5_10_LAYOUT
            .iter()
            .map(|(key, value)| {
                if *value == "n" {
                    format!("# {key} is not set\n")
                } else {
                    format!("{key}={value}\n")
                }
            })
            .collect::<String>();
        KernelConfig {
            values: parse(&text),
            text,
        }
    }

    #[test]
    fn the_measured_fixture_matches_the_series() {
        let config = fixture();
        assert!(config.layout_differences().is_empty());
        let series = series_5_10(Some(&config), "5.10.246-gki-g3e27bf130358");
        assert!(series.matched());
        assert!(!series.is_heuristic());
        assert!(series.label().starts_with("ikconfig:"));
    }

    #[test]
    fn a_single_layout_option_difference_is_a_mismatch() {
        let mut config = fixture();
        config
            .values
            .insert("CONFIG_UCLAMP_TASK".to_string(), "n".to_string());
        let differences = config.layout_differences();
        assert_eq!(differences.len(), 1);
        assert!(differences[0].starts_with("CONFIG_UCLAMP_TASK:"));
        let series = series_5_10(Some(&config), "5.10.246-gki");
        assert!(!series.matched());
        assert!(matches!(series, SeriesMatch::None { .. }));
    }

    #[test]
    fn no_ikconfig_falls_back_to_the_patch_range() {
        let series = series_5_10(None, "5.10.236-android12-9-build");
        assert!(series.matched());
        assert!(series.is_heuristic());
        assert!(series.label().contains("patch-range"));
        assert!(!series_5_10(None, "5.10.1-android12-9-build").matched());
        assert!(!series_5_10(None, "5.15.189-android13-build").matched());
    }

    #[test]
    fn config_lines_parse_set_and_unset_options() {
        let values = parse("# CONFIG_FOO is not set\nCONFIG_BAR=y\nCONFIG_BAZ=\"qux\"\n");
        assert_eq!(values["CONFIG_FOO"], "n");
        assert_eq!(values["CONFIG_BAR"], "y");
        assert_eq!(values["CONFIG_BAZ"], "\"qux\"");
    }
}
