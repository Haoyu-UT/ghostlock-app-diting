// Throwaway diagnostic: reproduce the multicast geometry derivation on the
// diting image with the crate's own disassembler, honoring the per-symbol
// window bound (start..min(start+0x2000, next symbol)). Not part of the build.
use ghostlock_extract::disasm::disassemble_range;
use regex::Regex;
use std::collections::HashMap;
use std::fs;

fn frames(lines: &[String]) -> (u64, u64) {
    let pre = Regex::new(r"(?i)\bstp\s+x29,\s*x30,\s*\[sp,\s*#-0x([0-9a-f]+)\]!").unwrap();
    let sub = Regex::new(r"(?i)\bsub\s+sp,\s*sp,\s*#0x([0-9a-f]+)").unwrap();
    let (mut total, mut first_sub) = (0u64, None::<u64>);
    for l in lines {
        if let Some(c) = pre.captures(l) {
            total += u64::from_str_radix(&c[1], 16).unwrap();
        }
        if first_sub.is_none() {
            if let Some(c) = sub.captures(l) {
                let v = u64::from_str_radix(&c[1], 16).unwrap();
                total += v;
                first_sub = Some(v);
            }
        }
    }
    (total, first_sub.unwrap_or(0))
}

fn main() {
    let img = fs::read("/tmp/diting.img").unwrap();
    let km = fs::read_to_string(
        "/home/haoyu/projects/redmi_ultra_k50_root/external/port/device-dump/run8/ghostlock-dumps/10-kallsyms.txt",
    )
    .unwrap();
    let mut addrs: HashMap<String, u64> = HashMap::new();
    for line in km.lines() {
        let mut it = line.split_whitespace();
        if let (Some(a), Some(_t), Some(n)) = (it.next(), it.next(), it.next()) {
            if let Ok(v) = u64::from_str_radix(a, 16) {
                if v != 0 {
                    addrs.entry(n.to_string()).or_insert(v);
                }
            }
        }
    }
    let text = addrs["_text"];
    let mut sorted: Vec<u64> = addrs
        .values()
        .copied()
        .filter(|v| *v > text && *v < text + 0x4000000)
        .collect();
    sorted.sort_unstable();
    sorted.dedup();

    let cap: u64 = 0x2000;
    let bound = |off: u64| -> u64 {
        let abs = text + off;
        let next = sorted.iter().find(|o| **o > abs).copied().unwrap_or(abs + cap);
        (off + cap).min(next - text)
    };
    let dump = |name: &str| -> Vec<String> {
        let off = addrs[name] - text;
        let stop = bound(off);
        println!("{name}: window 0x{off:x}..0x{stop:x} (len 0x{:x})", stop - off);
        let lines = disassemble_range(&img, off as usize, stop as usize).unwrap();
        let safe = name.replace("__", "");
        let _ = fs::write(format!("/tmp/disasm-{safe}.txt"), lines.join("\n"));
        lines
    };

    let mut frames_by: HashMap<&str, u64> = HashMap::new();
    for n in [
        "__arm64_sys_setsockopt",
        "__sys_setsockopt",
        "sock_common_setsockopt",
        "udp_setsockopt",
        "ip_setsockopt",
        "__arm64_sys_futex",
        "do_futex",
        "futex_wait_requeue_pi",
    ] {
        let lines = dump(n);
        let (tot, first) = frames(&lines);
        println!("   frame total=0x{tot:x} (first sub sp=0x{first:x})");
        frames_by.insert(n, tot);
    }

    println!("\n-- ip_setsockopt: mov w2,#0x108 + preceding add xN,sp,#..");
    let ip = dump("ip_setsockopt");
    let mov = Regex::new(r"(?i)\bmov\s+w2,\s*#0x108\b").unwrap();
    let ad = Regex::new(r"(?i)\badd\s+x\d+,\s*sp,\s*#0x([0-9a-f]+)").unwrap();
    let mut greqs = None;
    for (i, l) in ip.iter().enumerate() {
        if mov.is_match(l) {
            for prev in ip[..i].iter().rev().take(8) {
                if let Some(c) = ad.captures(prev) {
                    println!("   match at line {i}: {l} -> prev: {prev} (0x{})", &c[1]);
                    if greqs.is_none() {
                        greqs = Some(u64::from_str_radix(&c[1], 16).unwrap());
                    }
                    break;
                }
            }
        }
    }
    println!("   greqs chosen = {greqs:?}");

    println!("\n-- futex_wait_requeue_pi: add x27,sp + add xN,x27,#0x18");
    let fw = dump("futex_wait_requeue_pi");
    let set = Regex::new(r"(?i)\badd\s+x27,\s*sp,\s*#0x([0-9a-f]+)").unwrap();
    let idx = Regex::new(r"(?i)\badd\s+x\d+,\s*x27,\s*#0x18\b").unwrap();
    let mut wl = None;
    for (i, l) in fw.iter().enumerate() {
        if let Some(c) = set.captures(l) {
            let near = fw[i..(i + 64).min(fw.len())].iter().any(|x| idx.is_match(x));
            println!("   x27 add at line {i}: {l}  (x27+#0x18 within +64: {near})");
            if wl.is_none() && near {
                wl = Some(u64::from_str_radix(&c[1], 16).unwrap());
            }
        }
    }
    println!("   waiter_local chosen = {wl:?}");

    let sf: u64 = ["__arm64_sys_setsockopt", "__sys_setsockopt", "sock_common_setsockopt", "udp_setsockopt", "ip_setsockopt"]
        .iter().map(|n| frames_by[*n]).sum();
    let ff: u64 = ["__arm64_sys_futex", "do_futex", "futex_wait_requeue_pi"]
        .iter().map(|n| frames_by[*n]).sum();
    if let (Some(g), Some(w)) = (greqs, wl) {
        let sd = sf - g;
        let wd = ff - w;
        println!("\n== setsockopt_frames=0x{sf:x} greqs=0x{g:x} -> setsockopt_depth=0x{sd:x}");
        println!("== futex_frames=0x{ff:x} waiter_local=0x{w:x} -> waiter_depth=0x{wd:x}");
        println!("== waiter_off = 0x{:x} ({} )", sd - wd, sd - wd);
    }
    println!("\n(full disassemblies written to /tmp/disasm-*.txt)");
}
