// Throwaway diagnostic (local-only, do NOT commit).
//
// Purpose: print first_sp_frame() for each named symbol of a chain plus the
// sum, so a stack-depth comparison across builds can be done for an arbitrary
// syscall chain (e.g. the getsockopt chain for the tcp_zerocopy route).
//
// usage: cargo run --release --example frames -- <image> <sym>...

use ghostlock_extract::boot::BootImage;
use ghostlock_extract::derive::{relative_symbols, OBJDUMP_CAP};
use ghostlock_extract::disasm::{disassemble_range, first_sp_frame};
use ghostlock_extract::kallsyms;
use ghostlock_extract::kallsyms_finder;
use std::path::Path;

fn main() {
    let mut args = std::env::args().skip(1);
    let path = args.next().expect("usage: frames <image> <sym>...");
    let names: Vec<String> = args.collect();
    let boot = BootImage::load(Path::new(&path)).expect("load image");
    let btf_at = boot.embedded_btf_at();
    let btf_pair = btf_at.as_ref().map(|(offset, blob)| (*offset, blob.len()));
    let ks = kallsyms_finder::recover(&boot.kernel, btf_pair).expect("kallsyms");
    let base = kallsyms::unique(&ks.symbols, "_text")
        .or_else(|| kallsyms::unique(&ks.symbols, "_head"))
        .expect("base");
    let (rel, sorted) = relative_symbols(&ks.symbols, base);
    let mut total: u64 = 0;
    for name in &names {
        let off = match rel.get(name).and_then(|s| s.iter().next().copied()) {
            Some(v) => v,
            None => {
                println!("{name}: NOT FOUND");
                continue;
            }
        };
        let start = off as usize;
        let higher = sorted.iter().find(|o| **o as usize > start);
        let stop = (start + OBJDUMP_CAP).min(higher.map_or(start + OBJDUMP_CAP, |o| *o as usize));
        let lines = disassemble_range(&boot.kernel, start, stop).expect("disasm");
        match first_sp_frame(&lines, name) {
            Ok(f) => {
                println!("frame {name} = 0x{f:x}");
                total += f;
            }
            Err(e) => println!("frame {name}: FAIL {e}"),
        }
    }
    println!("sum = 0x{total:x} ({total})");
}
