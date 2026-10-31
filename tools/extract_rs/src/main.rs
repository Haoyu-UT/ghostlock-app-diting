use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use clap::Parser;

use ghostlock_extract::analysis;
use ghostlock_extract::anchor;
use ghostlock_extract::boot::{BootImage, MTK_DEFAULT_PHYS_LOAD, MTK_VADDR_BASE};
use ghostlock_extract::btf::Btf;
use ghostlock_extract::derive::{
    MULTICAST_5X_BUFFER_SIZE, PSELECT_ROUTE_NFDS, WaiterLayout, derive_cred_5x,
    derive_nf_logger_registration, derive_pselect_layout, ensure_rtmutex_43499_unpatched,
    multicast_waiter_off, relative_symbols,
};
use ghostlock_extract::error::{ExtractError, Result};
use ghostlock_extract::fact;
use ghostlock_extract::family;
use ghostlock_extract::fdt::{recover_kernel_phys_load, recover_kernel_phys_load_from_uefi};
use ghostlock_extract::dtbo;
use ghostlock_extract::ikconfig;
use ghostlock_extract::kallsyms;
use ghostlock_extract::kallsyms::Kallsyms;
use ghostlock_extract::kallsyms_finder;
use ghostlock_extract::layout;
use ghostlock_extract::options;
use ghostlock_extract::payload;
use ghostlock_extract::report;
use ghostlock_extract::structs;
use ghostlock_extract::symbols::{
    kernel_layout_verified, kernel_struct_macro, loggers_anchor_fallback, resolve_structs,
    resolve_symbols,
};
use ghostlock_extract::vendor_boot::{
    recover_kernel_phys_from_vendor_boot, PhysOffsetSource,
};

#[derive(Parser, Debug)]
#[command(
    name = "ghostlock-extract",
    about = "Extract GhostLock kernel offsets from boot.img / arm64 Image / payload.bin / OTA URL",
    after_help = "examples:\n  ghostlock-extract boot.img --format conf --out profile.conf\n  ghostlock-extract boot.img --format json --out offsets.json\n  ghostlock-extract https://host/payload.bin --format json --out offsets.json\nWhen --kallsyms is omitted, the embedded kallsyms table is recovered from the kernel image itself (no root needed); on a rooted phone /proc/kallsyms is used first."
)]
struct Cli {
    /// boot.img, raw arm64 Image, gzip Image, payload.bin, OTA ZIP, or http(s) OTA URL
    image: PathBuf,
    /// kallsyms text file (e.g. dumped from /proc/kallsyms); when omitted the
    /// embedded kallsyms table is recovered from the kernel image
    #[arg(long)]
    kallsyms: Option<PathBuf>,
    /// optional XBL xbl_config.img; derive kernel physical load from its FDT
    #[arg(long)]
    xbl_config: Option<PathBuf>,
    /// optional UEFI uefi.img; derive kernel physical load from its platform
    /// memory-map table when xbl_config carries no FDT memory map
    #[arg(long)]
    uefi: Option<PathBuf>,
    /// optional vendor_boot.img (MediaTek only); derive kernel physical load
    /// from its header kernel_addr and the offset from its embedded DTB
    #[arg(long)]
    vendor_boot: Option<PathBuf>,
    /// optional dtbo.img (MediaTek only); derive kernel_phys_offset from its
    /// DTBs' /memory node when vendor_boot.img carries no embedded DTB (or is
    /// not supplied)
    #[arg(long)]
    dtbo: Option<PathBuf>,
    /// kernel physical load address (hex or decimal); overrides defaults
    #[arg(long, value_parser = parse_int)]
    phys: Option<u64>,
    /// output format: text (JSON), json, or conf (flattened GLK profile HOCON)
    #[arg(long, value_parser = ["text", "json", "conf"], default_value = "text")]
    format: String,
    /// route written to --format conf; defaults to the analysis suggestion
    #[arg(long, value_parser = ["tcp_zerocopy", "select_stack", "multicast_waiter", "sigreturn"])]
    route: Option<String>,
    /// write the per-route feasibility verdicts as JSON (route, verdict,
    /// numbers, chosen route); exit 7 signals ambiguity
    #[arg(long)]
    feasible_out: Option<PathBuf>,
    /// write the option superset -- every feasible route with its geometry,
    /// every named anchor candidate with its page-free placement, and the
    /// page/auto/attested plans -- as JSON
    #[arg(long)]
    options_out: Option<PathBuf>,
    /// derive the route's lock-anchor region and emit it in --format conf.
    /// Any family; the profile carries it only when the route uses an anchor,
    /// and the app asks page-vs-anchor before export.
    #[arg(long)]
    anchor: bool,
    /// treat every unresolved symbol as optional (emit 0)
    #[arg(long)]
    allow_missing: bool,
    /// write output to a file instead of stdout
    #[arg(long)]
    out: Option<PathBuf>,
    /// skip disassembly-based derivation (pselect/loggers heuristics)
    #[arg(long)]
    no_disasm: bool,
    /// analyse the kernel (family, waiter layout, primitive, route candidates)
    /// and print a report instead of offsets
    #[arg(long)]
    analysis: bool,
    /// with --format conf, print the per-key fact table (value/domain/source/
    /// confidence) to stderr; the profile output is unchanged
    #[arg(long)]
    explain: bool,
    /// scan .bss for a usable lock-anchor region and report the
    /// route.select_stack.lock_anchor_* triple instead of offsets
    #[arg(long)]
    anchor_scan: bool,
    /// minimum symbol extent considered by --anchor-scan
    #[arg(long, value_parser = parse_int, default_value = "256")]
    anchor_min_extent: u64,
    /// assess one named symbol instead of ranking candidates; this is how the
    /// acceptance test checks a known-good region
    #[arg(long)]
    anchor_symbol: Option<String>,
    /// operator-supplied lock-anchor image offset; overrides the derived
    /// candidate. Requires --anchor-bytes and --anchor-stride. Logged as not
    /// derived; never emitted without the bytes/stride pair.
    #[arg(long, value_parser = parse_int)]
    anchor_image: Option<u64>,
    /// operator-supplied lock-anchor usable length in bytes (must be >= stride)
    #[arg(long, value_parser = parse_int)]
    anchor_bytes: Option<u64>,
    /// operator-supplied lock-anchor slot pitch in bytes
    #[arg(long, value_parser = parse_int)]
    anchor_stride: Option<u64>,
    /// operator-supplied W1 scratch image offset (page-free); requires
    /// --anchor and is emitted only when the value predicate holds
    #[arg(long, value_parser = parse_int)]
    w1_scratch_image: Option<u64>,
    /// named W1 second region resolved from kallsyms (e.g. bm_pmd,
    /// serial8250_ports, s3c24xx_serial_ports); requires --anchor
    #[arg(long)]
    w1_scratch_symbol: Option<String>,
    /// working directory for payload extraction and temp files; defaults to
    /// the system temp dir (pass an app-writable dir when running on Android)
    #[arg(long)]
    work_dir: Option<PathBuf>,
}

fn parse_int(text: &str) -> Result<u64> {
    let trimmed = text.trim();
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16)
            .map_err(|_| ExtractError::new(format!("invalid --phys value: {text}")))
    } else {
        trimmed
            .parse::<u64>()
            .map_err(|_| ExtractError::new(format!("invalid --phys value: {text}")))
    }
}

/// Human-readable byte size for download progress lines.
fn format_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

/// Progress callback for the selective payload download; prints a line about
/// every 3 seconds so the app log shows the download is alive.
fn download_progress() -> Option<payload_extract::input::ProgressCallback> {
    static NEXT_PRINT: AtomicU64 = AtomicU64::new(0);
    Some(std::sync::Arc::new(move |done: u64, total: u64| {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        if now < NEXT_PRINT.load(Ordering::Relaxed) {
            return;
        }
        NEXT_PRINT.store(now + 3000, Ordering::Relaxed);
        let percent = if total > 0 {
            done as f64 / total as f64 * 100.0
        } else {
            0.0
        };
        eprintln!(
            "download: {} / {} ({percent:.1}%)",
            format_size(done),
            format_size(total)
        );
    }))
}

/// Returns the file-based kallsyms source (--kallsyms or a readable
/// /proc/kallsyms), or None when the caller should recover symbols from the
/// kernel image instead.
fn obtain_kallsyms(provided: Option<&Path>) -> Result<Option<PathBuf>> {
    if let Some(provided) = provided {
        if !provided.is_file() {
            return Err(ExtractError::new(format!(
                "kallsyms file not found: {}",
                provided.display()
            )));
        }
        return Ok(Some(provided.to_path_buf()));
    }
    // On a rooted phone /proc/kallsyms is the natural source.
    // procfs stat reports len 0 for it, so probe readability with File::open.
    let proc_ksyms = Path::new("/proc/kallsyms");
    if proc_ksyms.is_file() && std::fs::File::open(proc_ksyms).is_ok() {
        return Ok(Some(proc_ksyms.to_path_buf()));
    }
    Ok(None)
}

/// Read and parse a kallsyms text file.
fn parse_kallsyms_file(path: &Path) -> Result<Kallsyms> {
    let parsed = std::fs::read_to_string(path)
        .map_err(|err| ExtractError::new(format!("cannot read kallsyms: {err}")))?;
    kallsyms::parse(&parsed)
}

/// Resolve the symbol table: --kallsyms / /proc/kallsyms first, otherwise
/// recover the embedded kallsyms table from the kernel image (no root needed).
fn resolve_kallsyms(
    boot: &BootImage,
    btf_at: Option<(usize, usize)>,
    cli: &Cli,
) -> Result<Kallsyms> {
    if let Some(path) = obtain_kallsyms(cli.kallsyms.as_deref())? {
        if cli.kallsyms.is_some() {
            // an explicit --kallsyms fails loudly instead of falling back
            return parse_kallsyms_file(&path);
        }
        // kptr_restrict zeroes every address; treat that as a missing table
        if let Ok(ks) = parse_kallsyms_file(&path) {
            if ks
                .symbols
                .values()
                .any(|addrs| addrs.iter().any(|&a| a != 0))
            {
                return Ok(ks);
            }
        }
    }
    kallsyms_finder::recover(&boot.kernel, btf_at)
        .map_err(|err| ExtractError::kallsyms(err.to_string()))
}

/// `selinux_state`'s field offsets: from the image's BTF when present (and
/// consistent), else the 5.10 release template. `None` = fail closed, the
/// profile omits the block and the native keeps its release-derived layout.
fn selinux_layout(btf: Option<&Btf>, release: &str) -> Option<(u32, u32, &'static str)> {
    if let Some(btf) = btf {
        let enforcing = btf.field("selinux_state", "enforcing")?;
        let initialized = btf.field("selinux_state", "initialized")?;
        if btf.field("selinux_state", "disabled").is_some() {
            eprintln!(
                "warning: selinux_state.disabled is present; the selinux block is omitted"
            );
            return None;
        }
        if enforcing != 0 || initialized >= 8 {
            eprintln!(
                "warning: unexpected selinux_state layout (enforcing {enforcing}, \
                 initialized {initialized}); the selinux block is omitted"
            );
            return None;
        }
        return Some((enforcing, initialized, "btf"));
    }
    /* No BTF: only the 5.10 series has a template; 5.15/6.1 and 6.6/6.12 are
     * BTF-carrying images, so a no-BTF member of those families fails closed. */
    let mut parts = release.split('.');
    let major: u32 = parts.next()?.parse().ok()?;
    let minor: u32 = parts.next()?.parse().ok()?;
    if major == 5 && minor == 10 {
        Some((0, 2, "release-template"))
    } else {
        None
    }
}

fn run(cli: &Cli) -> Result<i32> {
    let mut boot_path = cli.image.clone();
    let mut xbl_path = cli.xbl_config.clone();
    let mut uefi_path = cli.uefi.clone();
    let work_root = cli.work_dir.clone().unwrap_or_else(std::env::temp_dir);

    if payload::looks_like_payload(cli.image.to_string_lossy().as_ref()) {
        let work_dir = work_root.join(format!("ghostlock-payload-{}", std::process::id()));
        let input = cli.image.to_string_lossy();
        // Header + manifest only, then selective download of the partitions
        // the analysis needs; an empty list would pull the whole payload.
        let meta_view = payload::open_payload_meta(&input)
            .map_err(|err| ExtractError::new(format!("{err:#}")))?;
        let want = payload::analysis_partition_names(&meta_view)
            .map_err(|err| ExtractError::new(format!("{err:#}")))?;
        eprintln!("info: analyzing partitions: {}", want.join(", "));
        let payload_view = payload::open_payload_for(&input, &work_dir, &want, download_progress())
            .map_err(|err| ExtractError::new(format!("{err:#}")))?;
        let (extracted_boot, extracted_xbl, extracted_uefi) =
            payload::extract_analysis_inputs(&payload_view, &work_dir)
                .map_err(|err| ExtractError::new(format!("{err:#}")))?;
        boot_path = extracted_boot;
        xbl_path = extracted_xbl;
        uefi_path = extracted_uefi;
        eprintln!(
            "info: extracted boot={} xbl_config={} uefi={} from payload",
            boot_path.display(),
            xbl_path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "none".to_string()),
            uefi_path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "none".to_string())
        );
    }

    let boot = BootImage::load(&boot_path)?;
    let mut phys_source = "unset";
    let mut kernel_phys_load: Option<u64> = None;
    if let Some(xbl) = &xbl_path {
        match recover_kernel_phys_load(xbl) {
            Ok(phys) => {
                phys_source = "xbl_config FDT";
                kernel_phys_load = Some(phys);
            }
            Err(err) => {
                eprintln!("warning: xbl_config FDT parse failed: {err}; trying the uefi memory map")
            }
        }
    }
    if kernel_phys_load.is_none() {
        if let Some(uefi) = &uefi_path {
            match recover_kernel_phys_load_from_uefi(uefi) {
                Ok(phys) => {
                    phys_source = "uefi memory map";
                    eprintln!("info: kernel_phys_load=0x{phys:x} (uefi memory map)");
                    kernel_phys_load = Some(phys);
                }
                Err(err) => eprintln!(
                    "warning: uefi memory-map parse failed: {err}; proceeding with boot-only analysis"
                ),
            }
        }
    }
    if kernel_phys_load.is_none() && cli.phys.is_some() {
        phys_source = "--phys";
        kernel_phys_load = cli.phys;
    }

    // vendor_boot.img (MediaTek): kernel_addr supplies kernel_phys_load, and
    // the DTB in its dtb section supplies kernel_phys_offset from /memory.
    // When the image carries no usable DTB, the header's text-align pattern
    // is the fallback; dtbo.img names the same node when the bootloader takes
    // the DTB from elsewhere (dtb_size == 0).
    let mut vendor_boot_phys_offset: Option<u64> = None;
    if let Some(vb) = &cli.vendor_boot {
        match recover_kernel_phys_from_vendor_boot(vb) {
            Ok(info) => {
                if kernel_phys_load.is_none() {
                    kernel_phys_load = Some(info.kernel_addr);
                    phys_source = "vendor_boot header (MediaTek)";
                    eprintln!(
                        "info: vendor_boot; kernel_phys_load=0x{:x}",
                        info.kernel_addr
                    );
                } else {
                    eprintln!(
                        "info: vendor_boot; kernel_addr=0x{:x} \
                         (kernel_phys_load already resolved)",
                        info.kernel_addr
                    );
                }
                if let Some(err) = &info.dtb_error {
                    eprintln!("warning: vendor_boot embedded DTB unusable: {err}");
                }
                match info.source {
                    PhysOffsetSource::EmbeddedDtb => {
                        let offset = info.phys_offset.unwrap_or(0);
                        eprintln!(
                            "info: vendor_boot DTB /memory; \
                             kernel_phys_offset=0x{offset:x}"
                        );
                        if let (Some(header), Some(dtb)) =
                            (info.header_offset, info.phys_offset)
                        {
                            if header != dtb {
                                eprintln!(
                                    "warning: header alignment implies \
                                     kernel_phys_offset=0x{header:x}; the DTB \
                                     /memory node wins"
                                );
                            }
                        }
                    }
                    PhysOffsetSource::HeaderAlignment => {
                        let offset = info.phys_offset.unwrap_or(0);
                        eprintln!(
                            "info: vendor_boot header alignment; \
                             kernel_phys_offset=0x{offset:x}"
                        );
                    }
                    PhysOffsetSource::Unset => eprintln!(
                        "info: vendor_boot; kernel_phys_offset not provable \
                         (MiB-aligned kernel_addr and no usable embedded DTB); \
                         pass --dtbo to supply it"
                    ),
                }
                vendor_boot_phys_offset = info.phys_offset;
            }
            Err(err) => eprintln!(
                "warning: vendor_boot parse failed: {err}; trying other sources"
            ),
        }
    }
    if vendor_boot_phys_offset.is_none() {
        if let Some(dtbo_path) = &cli.dtbo {
            match dtbo::memory_base_from_path(dtbo_path) {
                Ok(base) => {
                    eprintln!("info: dtbo /memory; kernel_phys_offset=0x{base:x}");
                    vendor_boot_phys_offset = Some(base);
                }
                Err(err) => eprintln!("warning: dtbo parse failed: {err}"),
            }
        }
    }

    let btf_at = boot.embedded_btf_at();
    let ks = resolve_kallsyms(
        &boot,
        btf_at.as_ref().map(|(offset, blob)| (*offset, blob.len())),
        cli,
    )?;
    let symbols = ks.symbols;
    let text_base = kallsyms::unique(&symbols, "_text");
    let base = text_base.or_else(|| kallsyms::unique(&symbols, "_head"));
    let Some(base) = base else {
        return Err(ExtractError::new("_text/_head is not unique in kallsyms"));
    };

    /* The image's release scopes the series template/IKCONFIG predicate below. */
    let release = boot.release();
    /* /proc/iomem is deliberately not a source for the physical pair. Its
     * "Kernel code" start is seeded from _text on some images and _stext on
     * others (a per-image fact, not a release rule), and its System-RAM base
     * is not memstart_addr (arm64 rounds that down to ARM64_MEMSTART_ALIGN).
     * The load comes from xbl_config/uefi/vendor_boot or --phys; the offset
     * from vendor_boot/dtbo, or stays null for the native's compiled default. */
    let kernel_phys_offset: Option<u64> = vendor_boot_phys_offset;

    let (rel_symbols, sorted_offsets) = relative_symbols(&symbols, base);
    // stop early when remove_waiter() is fixed; --analysis reports it instead.
    let primitive = ensure_rtmutex_43499_unpatched(&boot.kernel, &rel_symbols, &sorted_offsets);
    match &primitive {
        Ok(remove_waiter) => eprintln!(
            "info: (CVE-2026-43499 primitive present \
             (remove_waiter@{remove_waiter:#x} still uses current)"
        ),
        Err(err) => {
            if !cli.analysis {
                eprintln!("error: {err}");
                return Ok(6);
            }
            eprintln!("warning: analysis continues: {err}");
        }
    }

    let btf_raw = btf_at.as_ref().map(|(_, blob)| blob.clone());
    let btf = btf_raw.as_deref().map(Btf::new).transpose()?;
    if btf.is_none() {
        eprintln!(
            "warning: embedded BTF not found; symbols come from kallsyms \
             and struct offsets fall back to target.h defaults"
        );
    }

    // The shared template's scope is the series that produced it. The image's
    // own embedded IKCONFIG is authoritative; the patch range is only the
    // lowest-priority fallback for a blob-less image.
    let kernel_config = match ikconfig::KernelConfig::from_image(&boot.kernel) {
        Ok(config) => Some(config),
        Err(err) => {
            eprintln!("warning: embedded IKCONFIG unavailable: {err}");
            None
        }
    };
    let series = release
        .as_deref()
        .map(|release| ikconfig::series_5_10(kernel_config.as_ref(), release))
        .unwrap_or(ikconfig::SeriesMatch::None {
            reason: "boot image carries no release string".to_string(),
        });
    let series_matched = series.matched();
    if release.as_deref().is_some_and(family::is_5_10) {
        match &series {
            ikconfig::SeriesMatch::Fingerprint { fingerprint } => eprintln!(
                "info: series ikconfig:{fingerprint} (layout fingerprint matches the \
                 measured 5.10 series)"
            ),
            ikconfig::SeriesMatch::PatchRange { range } => eprintln!(
                "warning: series patch-range:{range} (no IKCONFIG); every template value \
                 is a heuristic"
            ),
            ikconfig::SeriesMatch::None { reason } => eprintln!(
                "warning: series none: {reason}; template fields stay null"
            ),
        }
        if let Some(config) = &kernel_config {
            eprintln!("info: IKCONFIG full hash {}", config.full_hash());
        }
    }
    match release.as_deref() {
        Some(release) => {
            // 5.10 route geometry is derived from the image, so the 6.x
            // "unverified family" warning would misstate what was emitted.
            if !kernel_layout_verified(Some(release)) && !family::is_5_10(release) {
                let template = kernel_struct_macro(Some(release));
                eprintln!(
                    "warning: {release} is unverified{}; no family-derived \
                     geometry will be emitted",
                    template.map_or(String::new(), |name| format!(" (template {name} only)"))
                );
            }
        }
        None => {
            eprintln!("warning: boot image carries no kernel release string");
        }
    }
    if kernel_phys_load.is_none() && (boot.mtk_lz4 || boot.mtk_gzip) {
        if let Some(text_base) = text_base {
            match text_base.checked_sub(MTK_VADDR_BASE) {
                Some(derived) if derived == MTK_DEFAULT_PHYS_LOAD => {
                    eprintln!(
                        "info: MediaTek compressed image; _text confirms \
                         kernel_phys_load=0x{derived:x} (DRAM base)"
                    );
                    kernel_phys_load = Some(derived);
                    phys_source = "MediaTek DRAM base";
                }
                _ => {
                    eprintln!(
                        "warning: _text=0x{text_base:x} does not match the mtk \
                         DRAM-base mapping; kernel_phys_load left unset so the \
                         runtime derives it (pass --phys to override)"
                    );
                }
            }
        } else {
            eprintln!(
                "info: MediaTek compressed image; _text unavailable, leaving \
                 kernel_phys_load unset so the runtime derives it"
            );
        }
    }
    /* One canonical line for the app: which source supplied the physical pair.
     * The parse flow uses it to decide whether to ask for the next recommended
     * image (xbl_config -> uefi, vendor_boot -> dtbo). */
    eprintln!("info: phys_source={phys_source}");

    if cli.anchor && cli.format != "conf" {
        eprintln!("warning: --anchor only affects --format conf; ignoring");
    }
    if cli.route.is_some() && cli.format != "conf" {
        eprintln!("warning: --route only affects --format conf; ignoring");
    }

    if cli.analysis {
        let analysis_report = analysis::build(analysis::Input {
            release: release.as_deref(),
            kernel: &boot.kernel,
            symbols: &symbols,
            rel_symbols: &rel_symbols,
            sorted_offsets: &sorted_offsets,
            btf: btf.as_ref(),
            phys: kernel_phys_load,
            phys_source,
            primitive,
            allow_disasm: !cli.no_disasm,
        });
        let text = analysis::render(&analysis_report);
        if let Some(path) = &cli.feasible_out {
            write_feasible_out(
                path,
                release.as_deref().unwrap_or(""),
                &analysis_report.verdicts,
                analysis_report.suggestion,
            )?;
        }
        if let Some(out) = &cli.out {
            std::fs::write(out, text).map_err(|err| ExtractError::new(format!("{err}")))?;
        } else {
            print!("{text}");
        }
        return Ok(0);
    }

    if cli.anchor_scan {
        let text = anchor_scan(
            &rel_symbols,
            &boot.kernel,
            cli.anchor_min_extent,
            cli.anchor_symbol.as_deref(),
        );
        if let Some(out) = &cli.out {
            std::fs::write(out, text).map_err(|err| ExtractError::new(format!("{err}")))?;
        } else {
            print!("{text}");
        }
        return Ok(0);
    }

    let mut symbol_offsets = resolve_symbols(&symbols, base);

    let mut derived: BTreeMap<String, u64> = BTreeMap::new();
    let release_major = release
        .as_deref()
        .and_then(|release| release.split('.').next())
        .and_then(|part| part.parse::<u32>().ok());
    // The pselect derivation runs for every image with BTF, and for a 5.10
    // image without it (the waiter layout is a 5.10 codegen constant). A
    // derivation failure is Unknown; only a geometric impossibility is
    // Infeasible.
    let pselect_outcome = if cli.no_disasm {
        analysis::PselectOutcome::NotAttempted("--no-disasm")
    } else if btf.is_some() || release_major == Some(5) {
        match derive_pselect_layout(
            &boot.kernel,
            &rel_symbols,
            &sorted_offsets,
            btf.as_ref(),
            PSELECT_ROUTE_NFDS,
        ) {
            Ok(layout) => {
                let shift = layout.shift as i64 - 2;
                let frame_parts: Vec<String> = [
                    "frame_pselect_wrapper",
                    "frame_pselect_dispatch",
                    "frame_pselect_core",
                    "frame_futex_wrapper",
                    "frame_futex_dispatch",
                    "frame_futex_wait",
                ]
                .iter()
                .filter_map(|key| {
                    layout.frames.get(*key).map(|value| {
                        format!("{}={:#x}", key.split('_').nth(1).unwrap_or(key), value)
                    })
                })
                .collect();
                eprintln!(
                    "info: pselect chain {} frames={} buffer={:#x} waiter={:#x} \
                     shift={shift} (derived {} - 2)",
                    layout.chain,
                    frame_parts.join(" "),
                    layout.pselect_buffer,
                    layout.waiter_local,
                    layout.shift,
                );
                analysis::PselectOutcome::Derived(Box::new(layout))
            }
            Err(ExtractError::Infeasible { message, numbers }) => {
                eprintln!("warning: pselect route not feasible on this kernel: {message}");
                analysis::PselectOutcome::Infeasible { message, numbers }
            }
            Err(err) => {
                eprintln!("warning: pselect_waiter_shift derivation failed: {err}");
                analysis::PselectOutcome::Failed(err.to_string())
            }
        }
    } else {
        analysis::PselectOutcome::NotAttempted("no embedded BTF")
    };

    if !cli.no_disasm {
        match derive_nf_logger_registration(
            &boot.kernel,
            &rel_symbols,
            &sorted_offsets,
            btf.as_ref(),
        ) {
            Ok(info) => {
                derived.insert("off_slide_loggers_0_1".to_string(), info.loggers_0_1);
                eprintln!(
                    "info: nf_logger loggers={:#x} nfulnl_logger={:#x} ulog={} slot={:#x}{}",
                    info.loggers,
                    info.nfulnl_logger,
                    info.nf_log_type_ulog,
                    info.loggers_0_1,
                    if btf.is_none() {
                        " (no BTF; structure verified, measured anchor)"
                    } else {
                        ""
                    }
                );
            }
            Err(err) => eprintln!("warning: nf_logger derivation failed: {err}"),
        }
    } else {
        eprintln!("info: --no-disasm; nf_logger uses the family fallback");
    }

    /* `resolve_symbols` seeds the measured 5.10 anchor (`loggers+0x10`). Do
     * not let that constant reach another family: when the derivation did not
     * close, BTF supplies the enum index, 5.10 keeps the measured constant, and
     * every other family omits the field rather than shipping a foreign one. */
    if !derived.contains_key("off_slide_loggers_0_1") {
        let loggers =
            kallsyms::unique(&symbols, "loggers").and_then(|value| value.checked_sub(base));
        let ulog = btf
            .as_ref()
            .and_then(|btf| btf.enum_value("nf_log_type", "NF_LOG_TYPE_ULOG"));
        let (fallback, source) = loggers_anchor_fallback(
            loggers,
            ulog,
            release.as_deref().is_some_and(family::is_5_10),
        );
        symbol_offsets.insert("off_slide_loggers_0_1".to_string(), fallback);
        match source {
            "btf-enum" => eprintln!(
                "info: nf_logger anchor loggers+{:#x} from the BTF enum",
                ulog.unwrap_or(0) as u64 * 8
            ),
            "heuristic-5.10" => {
                eprintln!("warning: nf_logger anchor uses the measured 5.10 heuristic loggers+0x10")
            }
            _ => eprintln!("warning: nf_logger anchor omitted; no BTF enum and no family fallback"),
        }
    }

    let pselect_shift = match &pselect_outcome {
        analysis::PselectOutcome::Derived(layout) => Some(layout.shift as i64 - 2),
        _ if release_major == Some(5) => None,
        _ => {
            let shift = report::pselect_waiter_shift_for(release.as_deref());
            if let Some(shift) = shift {
                eprintln!(
                    "warning: using verified-family pselect_waiter_shift={shift}; \
                     image-specific disassembly derivation was unavailable"
                );
            } else {
                eprintln!(
                    "warning: pselect_waiter_shift unavailable; no family fallback \
                     is defined for this release"
                );
            }
            shift
        }
    };
    if let Some(slot) = derived.get("off_slide_loggers_0_1").copied() {
        symbol_offsets.insert("off_slide_loggers_0_1".to_string(), Some(slot));
    }
    let mut struct_offsets = resolve_structs(btf.as_ref());
    let mut field_sources: BTreeMap<String, String> = BTreeMap::new();
    // Per-image derivation first: init_task and copy_process locate the fields
    // the image itself can prove. A field that does not close stays absent.
    if btf.is_none() && cli.format == "conf" && !cli.no_disasm {
        let init_task = kallsyms::unique(&symbols, "init_task");
        let init_cred = kallsyms::unique(&symbols, "init_cred");
        let root_task_group = kallsyms::unique(&symbols, "root_task_group");
        if let (Some(init_task_va), Some(init_task_off)) = (
            init_task,
            symbol_offsets.get("off_init_task").copied().flatten(),
        ) {
            let derived = structs::derive_task_struct_5_10(
                &boot.kernel,
                &rel_symbols,
                &sorted_offsets,
                init_task_off,
                init_task_va,
                init_cred.unwrap_or(0),
                root_task_group.unwrap_or(0),
            );
            if !derived.values.is_empty() {
                for (name, value) in &derived.values {
                    struct_offsets.insert((*name).to_string(), Some(*value));
                    if let Some(source) = derived.sources.get(name) {
                        field_sources.insert((*name).to_string(), format!("derived:{source}"));
                    }
                }
                eprintln!(
                    "info: no BTF; task_struct derived from the image ({} fields)",
                    derived.values.len()
                );
            }
        }
    }
    // The template fills the profile contract, not the diagnostic report: the
    // JSON/text formats keep showing what the image itself yielded. It fills
    // only inside the measured series and only the fields the derivation did
    // not close; a fingerprint mismatch leaves the rest null.
    if btf.is_none() && cli.format == "conf" && series_matched {
        for (name, template_value) in family::TASK_FIELDS {
            match struct_offsets.get(*name).copied().flatten() {
                Some(derived) if derived != *template_value => eprintln!(
                    "warning: derived {name}={derived} differs from the measured-series \
                     template {template_value}; using derived"
                ),
                Some(_) => {}
                None => {
                    struct_offsets.insert((*name).to_string(), Some(*template_value));
                    let source = if series.is_heuristic() {
                        format!("template:{} heuristic", series.label())
                    } else {
                        format!("template:{}", series.label())
                    };
                    field_sources.insert((*name).to_string(), source);
                }
            }
        }
        eprintln!(
            "info: no BTF; task_struct template filled the remaining fields ({})",
            series.label()
        );
        if series.is_heuristic() {
            eprintln!(
                "warning: task_struct values are heuristic (patch-range series, no IKCONFIG)"
            );
        }
    }
    // Per-field provenance for the generation log. The app copies these lines
    // into the parse entry's meta; a later disagreement is reviewable without
    // re-running the extractor.
    if btf.is_none() && cli.format == "conf" {
        for name in struct_offsets.keys() {
            let source = field_sources.get(name).map(String::as_str).unwrap_or("null");
            eprintln!("info: field_source {name}={source}");
        }
    }

    let route_verdicts = analysis::route_verdicts(
        &boot.kernel,
        &rel_symbols,
        &sorted_offsets,
        btf.as_ref(),
        &pselect_outcome,
        !cli.no_disasm,
        release_major,
    );
    if cli.format == "conf" {
        for verdict in &route_verdicts {
            eprintln!(
                "info: route {} {}: {}",
                verdict.route,
                verdict.verdict.label(),
                verdict.reason
            );
        }
    }

    let missing: Vec<String> = symbol_offsets
        .iter()
        .filter(|(_, value)| value.is_none())
        .map(|(key, _)| key.clone())
        .collect();
    let mut tolerated: BTreeSet<String> = report::optional_symbols()
        .into_iter()
        .map(str::to_string)
        .collect();
    if cli.allow_missing {
        tolerated.extend(missing.iter().cloned());
    }
    let mut tolerated_missing: Vec<String> = missing
        .iter()
        .filter(|key| tolerated.contains(*key))
        .cloned()
        .collect();
    tolerated_missing.sort();
    for key in tolerated_missing {
        symbol_offsets.insert(key.clone(), Some(0));
        eprintln!(
            "warning: {key} not found in kallsyms; emitted 0x00000000 (runtime \
             falls back to target.h default)"
        );
    }
    // A conf candidate carries whatever the image yielded; the app's
    // pre-execution validation reports the gaps. Every other format keeps the
    // hard requirement.
    let candidate = cli.format == "conf";
    match report::require_fields(&symbol_offsets, &BTreeSet::new()) {
        Ok(()) => {}
        Err(err) if candidate => eprintln!(
            "warning: {err}; writing an unverified candidate (missing fields are omitted and \
             validated by the app)"
        ),
        Err(err) => return Err(err),
    }
    if btf.is_some() {
        let struct_fields_u64: BTreeMap<String, Option<u64>> = struct_offsets
            .iter()
            .map(|(key, value)| (key.clone(), value.map(|v| v as u64)))
            .collect();
        match report::require_fields(&struct_fields_u64, &report::optional_struct_fields()) {
            Ok(()) => {}
            Err(err) if candidate => eprintln!(
                "warning: {err}; writing an unverified candidate (missing fields are omitted and \
                 validated by the app)"
            ),
            Err(err) => return Err(err),
        }
    }
    if let Some(mm_size) = struct_offsets.get("struct_mm_struct").copied().flatten() {
        eprintln!(
            "info: sizeof(mm_struct)=0x{mm_size:X} (native spray default MM_STRUCT_SZ=0x500)"
        );
        if mm_size > 0x500 {
            eprintln!("warning: sizeof(mm_struct) exceeds the native MM_STRUCT_SZ default (0x500)");
        }
    }

    let btf_size = btf_raw.as_ref().map(|b| b.len()).unwrap_or(0);
    if cli.explain && cli.format != "conf" {
        eprintln!("warning: --explain is only meaningful with --format conf; ignoring");
    }
    if cli.options_out.is_some() && cli.format != "conf" {
        eprintln!("warning: --options-out is only meaningful with --format conf; ignoring");
    }
    let output = if cli.format == "conf" {
        let release_text = release
            .as_deref()
            .ok_or_else(|| ExtractError::new("--format conf requires a kernel release string"))?;
        let major = release_text
            .split('.')
            .next()
            .and_then(|part| part.parse::<u32>().ok());
        if major != Some(5) && major != Some(6) {
            return Err(ExtractError::new(format!(
                "--format conf needs a 5.x/6.x release, got {release_text}"
            )));
        }
        // Candidate output: emit everything the image actually yielded and
        // leave the rest out. Whether the result is complete enough to run is
        // decided by the app's pre-execution validation, not here.
        if cli.no_disasm && cli.route.is_none() {
            return Err(ExtractError::new(
                "--no-disasm with --format conf requires --route",
            ));
        }
        /* With `--options-out` an ambiguous pass still has to reach the common
         * facts so the superset can carry a cuttable profile; it exits 7 after
         * writing the document instead of returning here. */
        let mut ambiguous = false;
        let route = if let Some(forced) = cli.route.as_deref() {
            match route_verdicts
                .iter()
                .find(|verdict| verdict.route == forced)
            {
                Some(verdict) if verdict.verdict == analysis::Feasibility::Infeasible => {
                    eprintln!(
                        "error: forced route {forced} is infeasible on this kernel: {}",
                        verdict.reason
                    );
                    return Ok(3);
                }
                Some(verdict) => {
                    if verdict.verdict == analysis::Feasibility::Unknown {
                        eprintln!(
                            "warning: forced route {forced} is unverified (unknown): {}",
                            verdict.reason
                        );
                    }
                    Some(forced.to_string())
                }
                None => {
                    eprintln!("error: unknown route {forced}");
                    return Ok(3);
                }
            }
        } else {
            /* The fallback nomination: the 5.10 frame rule, or the family
             * heuristic for the other families. The verdict set decides first;
             * the nomination only breaks a zero-feasible tie. */
            let fallback = if release_major == Some(5) {
                family::route_hint(
                    &boot.kernel,
                    &rel_symbols,
                    &sorted_offsets,
                    release_text,
                )
            } else {
                let paths = analysis::probe_paths(
                    &symbols,
                    &boot.kernel,
                    &rel_symbols,
                    &sorted_offsets,
                );
                let pselect_derived =
                    matches!(pselect_outcome, analysis::PselectOutcome::Derived(_));
                let (suggested, _, reasons) = analysis::suggest_route(
                    pselect_derived,
                    &paths,
                    release.as_deref(),
                );
                suggested.map(|route| {
                    (route, reasons.first().cloned().unwrap_or_default())
                })
            };
            match analysis::select_route(&route_verdicts, fallback) {
                analysis::RouteSelection::Chosen {
                    route,
                    basis,
                    reason,
                } => {
                    eprintln!("info: route {route} selected ({basis:?}): {reason}");
                    Some(route.to_string())
                }
                analysis::RouteSelection::Ambiguous { routes } => {
                    if let Some(path) = &cli.feasible_out {
                        write_feasible_out(path, release_text, &route_verdicts, None)?;
                    }
                    eprintln!(
                        "error: more than one feasible route ({}); pass --route",
                        routes.join(", ")
                    );
                    if cli.options_out.is_some() {
                        ambiguous = true;
                        None
                    } else {
                        return Ok(7);
                    }
                }
                analysis::RouteSelection::None { reason } => {
                    eprintln!("warning: {reason}");
                    None
                }
            }
        };
        if let Some(path) = &cli.feasible_out {
            write_feasible_out(path, release_text, &route_verdicts, route.as_deref())?;
        }
        // select_stack is the only route that needs the derived pselect layout;
        // the 5.10 path already refused a forced Infeasible route, so this is
        // the pre-5.10 (family) path.
        if release_major != Some(5)
            && route
                .as_deref()
                .is_some_and(analysis::route_depends_on_pselect_layout)
        {
            if let analysis::PselectOutcome::Infeasible { message, .. } = &pselect_outcome {
                eprintln!("error: pselect route not feasible on this kernel: {message}");
                return Ok(3);
            }
        }
        let route_shift = if route.as_deref() == Some("select_stack") {
            pselect_shift.or_else(|| {
                if release_major == Some(5) {
                    eprintln!(
                        "warning: select_stack has no derived geometry; emitting the \
                         family waiter_shift={} as a labelled heuristic",
                        family::SELECT_WAITER_SHIFT
                    );
                    Some(family::SELECT_WAITER_SHIFT)
                } else {
                    None
                }
            })
        } else {
            pselect_shift
        };
        let sigreturn_offsets = route_verdicts
            .iter()
            .find(|verdict| {
                verdict.route == "sigreturn"
                    && verdict.verdict == analysis::Feasibility::Feasible
            })
            .and_then(|verdict| {
                Some((
                    *verdict.numbers.get("off_sve")?,
                    *verdict.numbers.get("off_plain")?,
                ))
            });
        if route.as_deref() == Some("sigreturn") && sigreturn_offsets.is_none() {
            eprintln!(
                "warning: sigreturn geometry has no image derivation; using the 5.10 \
                 patch-range constants as a heuristic"
            );
        }
        let mut geometry = route
            .as_deref()
            .map(|route| {
                report::conf_route_geometry_with_sigreturn(
                    route,
                    release_text,
                    route_shift,
                    sigreturn_offsets,
                    &struct_offsets,
                )
            })
            .unwrap_or_default();
        // 5.x multicast: replace the proven-constant waiter_off with the value
        // statically derived from this image's setsockopt/futex stack frames.
        // No device or root is involved; the A301SO image reproduces its
        // hardware-probed 0x60. The copy-window rule inside the derivation is
        // the same one the verdict applied.
        if route.as_deref() == Some("multicast_waiter") && !cli.no_disasm {
            let layout = if release_major == Some(5) {
                match btf.as_ref() {
                    Some(btf) => WaiterLayout::from_btf(btf).ok(),
                    None => Some(family::waiter_layout_5_10()),
                }
            } else {
                btf.as_ref().and_then(|btf| WaiterLayout::from_btf(btf).ok())
            };
            match layout.and_then(|layout| layout.lock.map(|lock| (layout, lock))) {
                Some((layout, lock)) => match multicast_waiter_off(
                    &boot.kernel,
                    &rel_symbols,
                    &sorted_offsets,
                    MULTICAST_5X_BUFFER_SIZE as u64,
                    layout.pi_tree_entry,
                    lock,
                ) {
                    Ok(geom) => {
                        eprintln!(
                            "info: multicast waiter_off derived = 0x{:x} \
                             (setsockopt depth 0x{:x} - futex depth 0x{:x})",
                            geom.waiter_off, geom.setsockopt_depth, geom.waiter_depth
                        );
                        for entry in geometry.iter_mut() {
                            if entry.0 == "waiter_off" {
                                entry.1 = geom.waiter_off as i64;
                            }
                        }
                    }
                    Err(err) => eprintln!(
                        "warning: static multicast waiter_off derivation failed: {err}; \
                         keeping the proven 5.x constant as a heuristic"
                    ),
                },
                None => eprintln!(
                    "warning: multicast waiter layout unavailable; keeping the proven 5.x \
                     constant as a heuristic"
                ),
            }
        } else if route.as_deref() == Some("multicast_waiter") {
            eprintln!(
                "warning: --no-disasm; keeping the proven 5.x multicast constants as a \
                 heuristic"
            );
        }
        // On-device derivation: the fake rt_mutex lives in a zeroed .bss
        // region; the anchor triple is per image (offset, safe length, slot
        // pitch). The pitch is the family's sizeof(rt_mutex): the anchor scan
        // does not derive it (docs/analysis/anchor-derivation-plan.md).
        let mut policy_scratch: Option<anchor::W1Scratch> = None;
        if cli.anchor {
            match (cli.anchor_image, cli.anchor_bytes, cli.anchor_stride) {
                (Some(image), Some(bytes), Some(stride)) => {
                    if stride == 0 || bytes < stride {
                        eprintln!(
                            "warning: lock anchor +0x{image:x}: 0x{bytes:x} bytes cannot \
                             hold one {stride}-byte slot; the triple is omitted"
                        );
                    } else {
                        eprintln!(
                            "warning: operator-supplied lock anchor +0x{image:x}, \
                             0x{bytes:x} bytes, stride {stride} -- NOT derived; the \
                             anchor gate for {release_text} stays closed until a device \
                             gate records a pass"
                        );
                        geometry.push(("lock_anchor_image", image as i64));
                        geometry.push(("lock_anchor_bytes", bytes as i64));
                        geometry.push(("lock_anchor_stride", stride as i64));
                    }
                }
                (None, None, None) => {
                    match route.as_deref() {
                        Some(route)
                            if route == "select_stack"
                                || route == "sigreturn"
                                || route == "multicast_waiter" =>
                        {
                            /* The policy chain (options::auto_plan): the
                             * first unconditioned region with a slot, then an
                             * unconditioned second region. The superset and
                             * the CLI must not disagree. */
                            let initialized = selinux_layout(btf.as_ref(), release_text)
                                .map(|(_, initialized, _)| initialized);
                            let candidates = options::scan_candidates(&options::CandidateInput {
                                kernel: &boot.kernel,
                                rel_symbols: &rel_symbols,
                                phys_load: kernel_phys_load,
                                phys_offset: kernel_phys_offset,
                                initialized,
                            });
                            let plan = options::auto_plan(route, &candidates);
                            match plan.anchor {
                                Some(anchor) => {
                                    let name = candidates
                                        .iter()
                                        .find(|candidate| {
                                            candidate.anchor.as_ref().map(|a| a.image)
                                                == Some(anchor.image)
                                        })
                                        .map(|candidate| {
                                            format!(
                                                "{} ({}{})",
                                                candidate.name,
                                                candidate.verdict,
                                                if candidate.conditioned {
                                                    ", conditioned"
                                                } else {
                                                    ""
                                                }
                                            )
                                        })
                                        .unwrap_or_else(|| "region".to_string());
                                    eprintln!(
                                        "info: auto plan anchor {name} +0x{:x}, 0x{:x} bytes, \
                                         stride {}, page_free={} ({})",
                                        anchor.image,
                                        anchor.bytes,
                                        anchor.stride,
                                        plan.page_free,
                                        plan.reason
                                    );
                                    geometry.push(("lock_anchor_image", anchor.image as i64));
                                    geometry.push(("lock_anchor_bytes", anchor.bytes as i64));
                                    geometry.push(("lock_anchor_stride", anchor.stride as i64));
                                    policy_scratch =
                                        plan.scratch.as_ref().map(|placement| anchor::W1Scratch {
                                            image: placement.image,
                                            window: placement.window,
                                            reserved_first: placement.reserved_first.unwrap_or(0),
                                            reserved_last: placement.reserved_last.unwrap_or(0),
                                            inside_anchor: placement.reserved_first.is_some(),
                                            source: anchor::ScratchSource::Policy,
                                        });
                                    if let Some(scratch) = policy_scratch {
                                        eprintln!(
                                            "info: auto plan scratch +0x{:x} ({}; {})",
                                            scratch.image,
                                            if scratch.inside_anchor {
                                                "in-anchor"
                                            } else {
                                                "second region"
                                            },
                                            if scratch.inside_anchor {
                                                format!(
                                                    "reserves anchor slots {}..{}",
                                                    scratch.reserved_first, scratch.reserved_last
                                                )
                                            } else {
                                                "no slot reservation".to_string()
                                            }
                                        );
                                    }
                                }
                                None => eprintln!(
                                    "warning: --anchor found no unconditional anchor region; \
                                     the profile falls back to the reclaimed page -- pass \
                                     --anchor-image/--anchor-bytes/--anchor-stride for a known \
                                     region"
                                ),
                            }
                        }
                        Some(route) => eprintln!(
                            "warning: --anchor: route {route} does not use a lock anchor; \
                             nothing emitted"
                        ),
                        None => {
                            eprintln!("warning: --anchor: no route selected; nothing emitted")
                        }
                    }
                }
                _ => eprintln!(
                    "warning: --anchor-image/--anchor-bytes/--anchor-stride must be given \
                     together; the anchor triple is omitted"
                ),
            }
        }
        match route.as_deref() {
            Some(route) if geometry.is_empty() => eprintln!(
                "warning: no image-derived geometry for route {route}; writing an unverified \
                 candidate route branch"
            ),
            Some(_) => {}
            None => eprintln!(
                "warning: no route could be inferred; writing release/common fields only \
                 (pass --route to select one)"
            ),
        }
        if route.as_deref() == Some("multicast_waiter")
            && !geometry.iter().any(|(key, _)| *key == "task_offset")
        {
            eprintln!(
                "warning: rt_mutex_waiter task/lock offsets are missing from BTF; the multicast \
                 geometry is partial"
            );
        }
        eprintln!(
            "info: {release_text} profile is an unverified candidate; the app validates fields \
             before any execution"
        );
        let cred: Vec<(String, String)> = if major == Some(5) {
            let derived_cred = btf.as_ref().and_then(|btf| {
                let init_cred_off = symbol_offsets.get("off_init_cred").copied().flatten()?;
                let size = btf.size("cred")?;
                match derive_cred_5x(btf, &boot.kernel, init_cred_off) {
                    Ok(cred) => Some(report::conf_cred_5x(&cred, size)),
                    Err(err) => {
                        eprintln!("warning: 5.x credential derivation failed: {err}");
                        None
                    }
                }
            });
            match derived_cred {
                Some(cred) => cred,
                None if series_matched => {
                    let init_cred_off = symbol_offsets.get("off_init_cred").copied().flatten();
                    let derived = init_cred_off.and_then(|offset| {
                        structs::derive_cred_layout_5_10(&boot.kernel, offset, base)
                    });
                    let cred = match derived {
                        Some(cred) => {
                            eprintln!(
                                "info: no BTF; cred caps and refs derived from init_cred \
                                 ({} refs, caps at {:#x})",
                                cred.refs.len(),
                                cred.caps_offset
                            );
                            field_sources.insert(
                                "cred_layout.caps".to_string(),
                                "derived:init_cred".to_string(),
                            );
                            field_sources.insert(
                                "cred_layout.refs".to_string(),
                                "derived:init_cred".to_string(),
                            );
                            Some(cred)
                        }
                        None => {
                            let fallback = init_cred_off.and_then(|offset| {
                                family::cred_from_image(&boot.kernel, offset, base)
                            });
                            if fallback.is_some() {
                                eprintln!(
                                    "warning: cred layout derivation failed; using the \
                                     measured-series offsets ({})",
                                    series.label()
                                );
                                field_sources.insert(
                                    "cred_layout.caps".to_string(),
                                    format!("family-constant:{}", series.label()),
                                );
                                field_sources.insert(
                                    "cred_layout.refs".to_string(),
                                    format!("family-constant:{}", series.label()),
                                );
                            }
                            fallback
                        }
                    };
                    field_sources.insert(
                        "cred_layout.copy_size".to_string(),
                        format!("template:{}", series.label()),
                    );
                    field_sources.insert(
                        "cred_layout.usage".to_string(),
                        "family-constant:5.10".to_string(),
                    );
                    match cred {
                        Some(cred) => {
                            let mut entries = report::conf_cred_5x(&cred, family::CRED_COPY_SIZE);
                            entries.push((
                                "usage_offset".to_string(),
                                family::CRED_USAGE_OFFSET.to_string(),
                            ));
                            entries.push(("ref3_offset".to_string(), "0".to_string()));
                            entries.push(("ref3_image".to_string(), "0".to_string()));
                            if series.is_heuristic() {
                                eprintln!(
                                    "warning: cred copy size and usage are heuristic \
                                     (patch-range series, no IKCONFIG)"
                                );
                            }
                            entries
                        }
                        None => {
                            eprintln!(
                                "warning: credential template omitted; init_cred reference \
                                 pointers are not canonical kernel VAs"
                            );
                            Vec::new()
                        }
                    }
                }
                None => {
                    eprintln!(
                        "warning: credential template omitted; the built-in profile must \
                         supply it"
                    );
                    Vec::new()
                }
            }
        } else {
            report::conf_cred_6x()
        };
        for name in [
            "cred_layout.caps",
            "cred_layout.refs",
            "cred_layout.copy_size",
            "cred_layout.usage",
        ] {
            if let Some(source) = field_sources.get(name) {
                eprintln!("info: field_source {name}={source}");
            }
        }
        let extra_offsets = report::ConfExtraOffsets {
            empty_zero_page: kallsyms::unique(&symbols, "empty_zero_page")
                .and_then(|value| value.checked_sub(base)),
        };
        let layouts = layout::derive(btf.as_ref(), release_text);
        /* Page-free Stage 1: the selinux field offsets and, when the route's
         * anchor triple was derived, the W1 scratch slot inside that region.
         * The scratch arithmetic needs the physical pair the native will use
         * (the profile's values, else the compiled defaults) and a 64 KiB
         * delta, so an unknown load or a misaligned delta fails closed. */
        let selinux_fields = selinux_layout(btf.as_ref(), release_text);
        let w1_scratch = (|| {
            if !cli.anchor {
                if cli.w1_scratch_image.is_some() || cli.w1_scratch_symbol.is_some() {
                    eprintln!(
                        "warning: --w1-scratch-image/--w1-scratch-symbol require \
                         --anchor (the effective page-free flag needs the route's \
                         anchor); the W1 scratch block is omitted"
                    );
                }
                return None;
            }
            let field = |name: &str| {
                geometry
                    .iter()
                    .find(|(key, _)| *key == name)
                    .map(|(_, value)| *value as u64)
            };
            let anchor_image = field("lock_anchor_image")?;
            let anchor_bytes = field("lock_anchor_bytes")?;
            let stride = field("lock_anchor_stride")?;
            let initialized = selinux_fields?.1;
            let load = kernel_phys_load?;
            let offset = kernel_phys_offset.unwrap_or(0x8000_0000);
            let delta = load.checked_sub(offset)?;
            if delta & 0xffff != 0 {
                eprintln!(
                    "warning: physical delta 0x{delta:x} is not 64 KiB-aligned; the \
                     W1 scratch block is omitted"
                );
                return None;
            }
            match (cli.w1_scratch_image, cli.w1_scratch_symbol.as_deref()) {
                (Some(_), Some(_)) => {
                    eprintln!(
                        "warning: --w1-scratch-image and --w1-scratch-symbol are \
                         mutually exclusive; the W1 scratch block is omitted"
                    );
                    None
                }
                (Some(image), None) => anchor::pick_w1_scratch_at(
                    image,
                    anchor_image,
                    anchor_bytes,
                    stride,
                    delta,
                    initialized,
                ),
                (None, Some(symbol)) => {
                    let Some(offset) = rel_symbols
                        .get(symbol)
                        .and_then(|offsets| offsets.iter().next().copied())
                    else {
                        eprintln!(
                            "warning: --w1-scratch-symbol {symbol}: not in kallsyms; \
                             the W1 scratch block is omitted"
                        );
                        return None;
                    };
                    let Some(next) = sorted_offsets.iter().copied().find(|off| *off > offset)
                    else {
                        eprintln!(
                            "warning: --w1-scratch-symbol {symbol}: no following symbol \
                             bounds the region; the W1 scratch block is omitted"
                        );
                        return None;
                    };
                    let scratch = anchor::pick_w1_scratch_in_symbol(
                        offset,
                        next - offset,
                        &boot.kernel,
                        delta,
                        initialized,
                    );
                    if scratch.is_none() {
                        eprintln!(
                            "warning: --w1-scratch-symbol {symbol}: no admissible window \
                             in 0x{:x} bytes; the W1 scratch block is omitted",
                            next - offset
                        );
                    }
                    scratch
                }
                (None, None) => policy_scratch.or_else(|| {
                    anchor::pick_w1_scratch(
                        anchor_image,
                        anchor_bytes,
                        stride,
                        delta,
                        initialized,
                    )
                }),
            }
        })();
        let stage1 = selinux_fields.map(|(enforcing, initialized, source)| report::Stage1Conf {
            selinux_enforcing: enforcing,
            selinux_initialized: initialized,
            selinux_source: source,
            w1_scratch,
        });
        let inputs = report::ConfInputs {
            release: release_text,
            phys: kernel_phys_load,
            /* DRAM base: from the vendor_boot/dtbo DTB /memory node, or left
             * null so the native's compiled default applies. */
            phys_offset: kernel_phys_offset,
            phys_source,
            symbols: &symbol_offsets,
            structs: &struct_offsets,
            route: route.as_deref(),
            route_geometry: &geometry,
            cred: &cred,
            extra_offsets: &extra_offsets,
            layouts: Some(&layouts),
            stage1,
        };
        /* The option superset, written once the common profile facts exist so
         * it can be cut into any plan. An ambiguous route set reaches this
         * point and exits 7 below, after the document is on disk. */
        if let Some(path) = &cli.options_out {
            let mut all_geometry: BTreeMap<String, BTreeMap<String, i64>> = BTreeMap::new();
            for verdict in &route_verdicts {
                if verdict.verdict != analysis::Feasibility::Feasible {
                    continue;
                }
                let shift = if verdict.route == "select_stack" {
                    pselect_shift.or_else(|| {
                        (release_major == Some(5)).then_some(family::SELECT_WAITER_SHIFT)
                    })
                } else {
                    pselect_shift
                };
                let mut geometry: BTreeMap<String, i64> =
                    report::conf_route_geometry_with_sigreturn(
                        verdict.route,
                        release_text,
                        shift,
                        sigreturn_offsets,
                        &struct_offsets,
                    )
                    .into_iter()
                    .map(|(key, value)| (key.to_string(), value))
                    .collect();
                if verdict.route == "multicast_waiter" && !cli.no_disasm {
                    let layout = if release_major == Some(5) {
                        match btf.as_ref() {
                            Some(btf) => WaiterLayout::from_btf(btf).ok(),
                            None => Some(family::waiter_layout_5_10()),
                        }
                    } else {
                        btf.as_ref().and_then(|btf| WaiterLayout::from_btf(btf).ok())
                    };
                    if let Some((layout, lock)) =
                        layout.and_then(|layout| layout.lock.map(|lock| (layout, lock)))
                    {
                        if let Ok(geom) = multicast_waiter_off(
                            &boot.kernel,
                            &rel_symbols,
                            &sorted_offsets,
                            MULTICAST_5X_BUFFER_SIZE as u64,
                            layout.pi_tree_entry,
                            lock,
                        ) {
                            geometry.insert("waiter_off".to_string(), geom.waiter_off as i64);
                        }
                    }
                }
                all_geometry.insert(verdict.route.to_string(), geometry);
            }
            let common_text = report::render_conf(&report::ConfInputs {
                release: release_text,
                phys: kernel_phys_load,
                phys_offset: kernel_phys_offset,
                phys_source,
                symbols: &symbol_offsets,
                structs: &struct_offsets,
                route: None,
                route_geometry: &[],
                cred: &cred,
                extra_offsets: &extra_offsets,
                layouts: Some(&layouts),
                stage1: stage1.map(|stage| report::Stage1Conf {
                    w1_scratch: None,
                    ..stage
                }),
            });
            let initialized = selinux_fields.map(|(_, initialized, _)| initialized);
            let input = options::Input {
                release: release_text,
                kernel_major: major,
                phys_load: kernel_phys_load,
                phys_offset: kernel_phys_offset,
                phys_source,
                verdicts: &route_verdicts,
                geometry: &all_geometry,
                initialized,
                kernel: &boot.kernel,
                rel_symbols: &rel_symbols,
                common_profile: &common_text,
            };
            let superset = options::build(&input);
            let text = serde_json::to_string_pretty(&superset)
                .map_err(|err| ExtractError::new(format!("cannot serialize options: {err}")))?;
            std::fs::write(path, text + "\n")
                .map_err(|err| ExtractError::new(format!("{err}")))?;
            eprintln!("info: options superset written to {}", path.display());
        }
        if ambiguous {
            return Ok(7);
        }
        if cli.explain {
            let provenance = fact::Provenance {
                btf_present: btf.is_some(),
                phys_source,
                route_forced: cli.route.is_some(),
                field_sources: &field_sources,
                release: release_text,
                layouts: &layouts,
            };
            eprint!("{}", fact::explain_conf(&inputs, &provenance).render());
        }
        report::render_conf(&inputs)
    } else {
        let report_value = report::build_report(
            release.as_deref(),
            base,
            kernel_phys_load,
            &symbol_offsets,
            &struct_offsets,
            btf_size,
            pselect_shift,
        );
        serde_json::to_string_pretty(&report_value).unwrap() + "\n"
    };
    if let Some(out) = &cli.out {
        std::fs::write(out, output).map_err(|err| ExtractError::new(format!("{err}")))?;
    } else {
        print!("{output}");
    }
    let remaining: Vec<String> = symbol_offsets
        .iter()
        .map(|(key, value)| (key.clone(), value.map(|v| v as u64)))
        .chain(
            struct_offsets
                .iter()
                .map(|(key, value)| (key.clone(), value.map(|v| v as u64))),
        )
        .filter(|(_, value)| value.is_none())
        .map(|(key, _)| key.clone())
        .collect();
    if !remaining.is_empty() {
        eprintln!("missing: {}", remaining.join(", "));
    }
    Ok(0)
}

fn main() {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(code) => std::process::exit(code),
        Err(err) => {
            eprintln!("error: {err}");
            // Exit codes let the app distinguish failure classes:
            // 2 generic parse failure,
            // 3 pselect route infeasible,
            // 4 missing required offsets,
            // 5 kallsyms recovery failure,
            // 6 primitive already fixed.
            let code = match &err {
                ExtractError::Infeasible { .. } => 3,
                ExtractError::Unsupported(_) => 4,
                ExtractError::AlreadyFixed(_) => 6,
                ExtractError::Kallsyms(_) => 5,
                ExtractError::Message(_) => 2,
            };
            std::process::exit(code);
        }
    }
}

/// Render the `--feasible-out` JSON: the per-route verdicts the app's
/// two-pass ambiguity flow reads, plus the route this pass chose (null when
/// the routes are ambiguous or none is feasible).
#[derive(serde::Serialize)]
struct FeasibleOut<'a> {
    release: &'a str,
    routes: &'a [analysis::RouteVerdict],
    chosen: Option<&'a str>,
}

fn write_feasible_out(
    path: &Path,
    release: &str,
    verdicts: &[analysis::RouteVerdict],
    chosen: Option<&str>,
) -> Result<()> {
    let text = serde_json::to_string_pretty(&FeasibleOut {
        release,
        routes: verdicts,
        chosen,
    })
    .map_err(|err| ExtractError::new(format!("cannot serialize feasible-out: {err}")))?;
    std::fs::write(path, text + "\n").map_err(|err| ExtractError::new(format!("{err}")))
}

/// Render the `--anchor-scan` report.
///
/// See `anchor.rs` for what is derived and `docs/analysis/anchor-derivation-plan.md`
/// for why: the length comes from extending until something live stands in the
/// way, not from a symbol size, because kallsyms does not store sizes and the
/// extent is an upper bound that was already wrong once.
fn anchor_scan(
    rel: &BTreeMap<String, BTreeSet<u64>>,
    kernel: &[u8],
    min_extent: u64,
    only: Option<&str>,
) -> String {
    let g = |n: &str| -> u64 {
        rel.get(n).and_then(|s| s.iter().next().copied()).unwrap_or(0)
    };
    let bounds = anchor::Bounds {
        text_start: g("_text"),
        text_end: g("_etext"),
        init_start: g("_sinittext"),
        init_end: g("_einittext"),
        bss_start: g("__bss_start"),
        bss_end: g("__bss_stop"),
        ro_after_init_end: g("__end_ro_after_init"),
    };

    let mut out = String::new();
    out.push_str(&format!(
        "[anchor] .bss [+0x{:x}, +0x{:x}), writable from +0x{:x}; \
text [+0x{:x}, +0x{:x}), init [+0x{:x}, +0x{:x})\n",
        bounds.bss_start, bounds.bss_end, bounds.ro_after_init_end,
        bounds.text_start, bounds.text_end, bounds.init_start, bounds.init_end,
    ));

    let mut cands = anchor::candidates(rel, &bounds, min_extent);
    if let Some(name) = only {
        /* A named symbol does not have to clear the extent filter: the point of
         * asking about it is to check the scan against a region already known to
         * work, whatever its extent. */
        let mut all: Vec<(u64, String)> = Vec::new();
        for (n, offs) in rel {
            for o in offs {
                all.push((*o, n.clone()));
            }
        }
        all.sort();
        cands = all
            .iter()
            .enumerate()
            .filter(|(_, (_, n))| n == name)
            .map(|(i, (off, n))| anchor::Candidate {
                name: n.clone(),
                offset: *off,
                extent: all
                    .get(i + 1)
                    .map(|(o, _)| o.saturating_sub(*off))
                    .unwrap_or(bounds.bss_end.saturating_sub(*off)),
            })
            .collect();
        if cands.is_empty() {
            return format!("[anchor] symbol {name:?} not found in kallsyms\n");
        }
    }
    if cands.is_empty() {
        out.push_str("[anchor] no candidate symbols in writable .bss\n");
        return out;
    }

    let refs = anchor::scan_references(kernel, &bounds);
    out.push_str(&format!(
        "[anchor] {} candidate symbol(s); {} direct reference(s) found in text\n\n",
        cands.len(),
        refs.len()
    ));

    for cand in cands.iter().take(5) {
        let a = anchor::assess(cand, &refs, rel, &bounds);
        out.push_str(&format!(
            "[anchor] {}  image +0x{:x}  extent 0x{:x}\n",
            a.candidate.name, a.candidate.offset, a.candidate.extent
        ));
        out.push_str(&format!(
            "  references : {} live read, {} live write, {} init, {} materialized\n",
            a.live_reads.len(),
            a.live_writes.len(),
            a.init_refs.len(),
            a.materializations.len()
        ));
        for r in a.materializations.iter().take(3) {
            out.push_str(&format!(
                "     addr  +0x{:x} at +0x{:x} (materialized; indexed/call uses are invisible)\n",
                r.target, r.site
            ));
        }
        for r in a.live_reads.iter().take(3) {
            out.push_str(&format!(
                "     read  +0x{:x} width {} at +0x{:x}\n",
                r.target, r.width, r.site
            ));
        }
        for w in a.live_writes.iter().take(3) {
            out.push_str(&format!(
                "     write +0x{:x} width {} at +0x{:x}\n",
                w.target, w.width, w.site
            ));
        }
        out.push_str(&format!(
            "  safe length: 0x{:x}   (stopped by: {})\n",
            a.safe_len, a.stopped_by
        ));
        out.push_str(&format!(
            "  first access: {}\n",
            a.first_access
                .map(|o| format!("+0x{o:x}"))
                .unwrap_or_else(|| "none".to_string())
        ));
        out.push_str(&format!(
            "  clean prefix: 0x{:x}   (first read/write/init access, at stride {})\n",
            anchor::clean_prefix(&a, family::ANCHOR_STRIDE),
            family::ANCHOR_STRIDE,
        ));
        out.push_str(&format!("  verdict    : {}\n", a.verdict.label()));
        out.push_str(&format!(
            "  stride     : not derived -- the PI walk's lock-relative accesses need \
register provenance across branches; supply it in the profile (see the design doc)\n"
        ));
        match anchor::profile_triple(&a) {
            Some((image, bytes, stride)) => {
                out.push_str(&format!(
                    "  => lock_anchor_image = {}   (place under the selected route)\n",
                    image
                ));
                out.push_str(&format!(
                    "     lock_anchor_bytes = {}   (safe prefix 0x{:x} rounded down)\n",
                    bytes, a.safe_len
                ));
                out.push_str(&format!("     lock_anchor_stride = {}\n\n", stride));
            }
            None => out.push_str(
                "  => no triple: the safe prefix is shorter than one lock slot\n\n",
            ),
        }
    }
    out
}
