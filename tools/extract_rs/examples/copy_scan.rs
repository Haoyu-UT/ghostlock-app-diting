// Throwaway diagnostic (local-only, do NOT commit).
//
// copy_scan -- the direction-1 delivery sweep, mechanical pass.
//
// Walks every __arm64_sys_* direct-call chain and finds user-copy destinations
// that are stack addresses: (a) direct copy-call destinations whose pointer is
// sp-relative, and (b) sp-relative pointers stored INTO stack slots (how
// arrays passed by address appear -- e.g. import_iovec's `iov` pointer, or
// get_fd_set's fdset argument). Then applies the depth law from
// external/port/k81/delivery-sweep.txt:
//
//   depth(local at sp+off in F) = Sigma(F) - off      (Sigma = chain frame sum)
//   waiter byte b sits at depth WAIT_DEPTH - b
//   an S-byte array at base depth D covers bytes
//       [WAIT_DEPTH - D - (S - 8),  WAIT_DEPTH - D]
//
// Default geometry is the 5.10.81 waiter depth (0x1c0); pass the depth as a
// second argument for a control (5.10.236 = 0x210).
//
// usage: cargo run --release --example copy_scan -- <image> [wait_depth_hex]

use ghostlock_extract::boot::BootImage;
use ghostlock_extract::derive::{relative_symbols, OBJDUMP_CAP};
use ghostlock_extract::disasm::{disassemble_range, first_sp_frame};
use ghostlock_extract::kallsyms;
use ghostlock_extract::kallsyms_finder;
use regex::Regex;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::path::Path;

#[derive(Clone, Debug)]
struct Site {
    off: u64,          // sp-relative offset (reference frame) of the destination/array
    size: Option<u64>, // bytes when a constant size was visible
    callee: String,    // copy function, or "ptr-store" for category (b)
    kind: char,        // 'a' direct destination, 'b' sp-pointer stored to a slot
    idx: u32,          // instruction index of the call/store, for K3 ordering
}

struct FnInfo {
    frame: u64,
    edges: Vec<(u64, bool)>, // (raw target, is tail call)
    sites: Vec<Site>,
    store_marks: Vec<(u32, i64)>, // (instruction idx, sp slot) of every computable store
}

fn reg_index(tok: &str) -> Option<usize> {
    let t = tok.trim();
    let b = t.as_bytes();
    if b.len() < 2 || (b[0] != b'x' && b[0] != b'w') {
        return None;
    }
    let n: usize = t[1..].parse().ok()?;
    (n <= 30).then_some(n)
}

/// The GKI build emits per-TU instances of static-inline helpers with a
/// `.<digits>` suffix (`_copy_from_user.15270`, ...). Canonicalize those back
/// to the helper's name so table lookups match.
fn canon(name: &str) -> &str {
    if let Some((head, tail)) = name.rsplit_once('.') {
        if !tail.is_empty() && tail.chars().all(|c| c.is_ascii_digit()) {
            return head;
        }
    }
    name
}

/// Parse `[base, #+/-0x..]` (or `[base]`) from an operand string.
/// Base is `None` for sp, `Some(r)` for a general register. Returns None when
/// the offset is not a constant (register-offset forms).
fn mem_operand(op: &str) -> Option<(Option<usize>, i64)> {
    let open = op.find('[')?;
    let close = op[open..].find(']')? + open;
    let inner = &op[open + 1..close];
    let mut parts = inner.split(',').map(str::trim);
    let base_tok = parts.next()?;
    let base = if base_tok == "sp" {
        None
    } else {
        Some(reg_index(base_tok)?)
    };
    let off = match parts.next() {
        None => 0,
        Some(tok) => {
            let tok = tok.trim();
            if let Some(hex) = tok.strip_prefix('#') {
                if let Some(neg) = hex.strip_prefix("-0x") {
                    -i64::from_str_radix(neg, 16).ok()?
                } else if let Some(pos) = hex.strip_prefix("0x") {
                    i64::from_str_radix(pos, 16).ok()?
                } else {
                    return None;
                }
            } else {
                return None; // register offset / shift form: not a constant slot
            }
        }
    };
    Some((base, off))
}

/// Post-index writeback immediate, e.g. `[sp], #0x10` -> Some(0x10).
fn post_index(op: &str) -> Option<i64> {
    let after = op.split(']').nth(1)?.trim();
    let tok = after.strip_prefix(',')?.trim().strip_prefix('#')?;
    if let Some(neg) = tok.strip_prefix("-0x") {
        Some(-i64::from_str_radix(neg, 16).ok()?)
    } else {
        Some(i64::from_str_radix(tok.strip_prefix("0x")?, 16).ok()?)
    }
}

fn scan_lines(
    lines: &[String],
    frame: u64,
    copy_tbl: &HashMap<String, (usize, Option<usize>)>,
    resolve: &dyn Fn(u64) -> Option<(u64, String)>,
) -> (Vec<(u64, bool)>, Vec<Site>, Vec<(u32, i64)>) {
    let mut regs: [Option<i64>; 31] = [None; 31]; // x0..x30 -> reference-relative sp offset
    let mut imms: [Option<u64>; 31] = [None; 31]; // constant materialized in xN/wN
    let mut slots: HashMap<i64, i64> = HashMap::new(); // sp slot -> stored sp pointer
    let mut sites: Vec<Site> = Vec::new();
    let mut store_marks: Vec<(u32, i64)> = Vec::new();
    let mut branches: Vec<(u64, bool)> = Vec::new();
    let mut sp_delta: i64 = 0;

    let re_add_sp_imm = Regex::new(r"(?i)^add\s+(x\d+),\s*sp,\s*#(0x[0-9a-f]+)$").unwrap();
    let re_add_reg_imm = Regex::new(r"(?i)^add\s+(x\d+),\s*(x\d+),\s*#(0x[0-9a-f]+)$").unwrap();
    let re_mov_reg = Regex::new(r"(?i)^mov\s+(x\d+),\s*(x\d+)$").unwrap();
    let re_mov_imm = Regex::new(r"(?i)^mov\s+([xw]\d+),\s*#(0x[0-9a-f]+)$").unwrap();
    let re_branch = Regex::new(r"(?i)^(bl|b)\s+0x([0-9a-f]+)$").unwrap();
    let re_sub_sp = Regex::new(r"(?i)^sub\s+sp,\s*sp,\s*#(0x[0-9a-f]+)$").unwrap();
    let re_add_sp = Regex::new(r"(?i)^add\s+sp,\s*sp,\s*#(0x[0-9a-f]+)$").unwrap();

    let rel_of = |sp_delta: i64, k: i64| frame as i64 - sp_delta + k;

    for (line_no, line) in lines.iter().enumerate() {
        let idx = line_no as u32;
        let (mnemonic, operands) = ghostlock_extract::disasm::split_line(line);
        let m = mnemonic.to_ascii_lowercase();
        let ops: Vec<&str> = operands.split(',').map(str::trim).collect();

        // --- stack pointer adjustments ---
        if let Some(c) = re_sub_sp.captures(line) {
            sp_delta += i64::from_str_radix(&c[1][2..], 16).unwrap_or(0);
            continue;
        }
        if let Some(c) = re_add_sp.captures(line) {
            sp_delta -= i64::from_str_radix(&c[1][2..], 16).unwrap_or(0);
            continue;
        }

        // --- stores (str/stp/stur/...): slot-value tracking + sp-pointer sites ---
        if m.starts_with("st") {
            if let Some((base, k)) = mem_operand(&operands) {
                let slot = match base {
                    None => Some(rel_of(sp_delta, k)), // sp
                    Some(r) => regs.get(r).copied().flatten().map(|v| v + k),
                };
                if let Some(slot) = slot {
                    if store_marks.len() < 512 {
                        store_marks.push((idx, slot));
                    }
                    let mut srcs: Vec<&str> = Vec::new();
                    if m == "stp" && ops.len() >= 2 {
                        srcs.push(ops[0]);
                        srcs.push(ops[1]);
                    } else {
                        srcs.push(ops[0]);
                    }
                    for (i, src) in srcs.iter().enumerate() {
                        let v = reg_index(src).and_then(|r| regs[r]);
                        let at = slot + (i as i64) * 8;
                        match v {
                            Some(v) => {
                                slots.insert(at, v);
                                sites.push(Site {
                                    off: v as u64,
                                    size: None,
                                    callee: "ptr-store".into(),
                                    kind: 'b',
                                    idx,
                                });
                            }
                            None => {
                                slots.remove(&at);
                            }
                        }
                    }
                }
                if base.is_none() {
                    // pre-index writeback (`[sp, #-0x50]!`): sp += k
                    if operands.contains("]!") {
                        sp_delta -= k;
                    } else if let Some(pi) = post_index(&operands) {
                        sp_delta -= pi;
                    }
                }
            }
            continue;
        }

        // --- address materialization ---
        if let Some(c) = re_add_sp_imm.captures(line) {
            let reg = reg_index(&c[1]).unwrap();
            regs[reg] = Some(rel_of(sp_delta, i64::from_str_radix(&c[2][2..], 16).unwrap_or(0)));
            imms[reg] = None;
            continue;
        }
        if let Some(c) = re_add_reg_imm.captures(line) {
            let dst = reg_index(&c[1]).unwrap();
            let src = reg_index(&c[2]).unwrap();
            regs[dst] = regs[src].map(|v| v + i64::from_str_radix(&c[3][2..], 16).unwrap_or(0));
            imms[dst] = None;
            continue;
        }
        if let Some(c) = re_mov_reg.captures(line) {
            let dst = reg_index(&c[1]).unwrap();
            let src = reg_index(&c[2]).unwrap();
            regs[dst] = regs[src];
            imms[dst] = imms[src];
            continue;
        }
        if let Some(c) = re_mov_imm.captures(line) {
            let reg = reg_index(&c[1]).unwrap();
            regs[reg] = None;
            imms[reg] = u64::from_str_radix(&c[2][2..], 16).ok();
            continue;
        }

        // --- loads: a pointer loaded back out of a known slot is still sp-relative ---
        if m == "ldr" || m == "ldur" || m == "ldar" {
            if let (Some(dst), Some(mem)) = (ops.first(), ops.get(1).and_then(|o| mem_operand(o))) {
                if let Some(dr) = reg_index(dst) {
                    let slot = match mem.0 {
                        None => Some(rel_of(sp_delta, mem.1)),
                        Some(r) => regs.get(r).copied().flatten().map(|v| v + mem.1),
                    };
                    regs[dr] = if dst.trim().starts_with('x') {
                        slot.and_then(|s| slots.get(&s).copied())
                    } else {
                        None
                    };
                    imms[dr] = None;
                    continue;
                }
            }
        }
        if m == "ldp" || m == "ldpsw" {
            if let Some(mem) = ops.get(2).and_then(|o| mem_operand(o)) {
                let base = match mem.0 {
                    None => Some(rel_of(sp_delta, mem.1)),
                    Some(r) => regs.get(r).copied().flatten().map(|v| v + mem.1),
                };
                if let Some(base) = base {
                    for (i, tok) in ops.iter().take(2).enumerate() {
                        if let Some(dr) = reg_index(tok) {
                            let at = base + (i as i64) * 8;
                            regs[dr] = if tok.trim().starts_with('x') {
                                slots.get(&at).copied()
                            } else {
                                None
                            };
                            imms[dr] = None;
                        }
                    }
                    continue;
                }
            }
        }

        // --- calls ---
        if let Some(c) = re_branch.captures(line) {
            let is_bl = c[1].eq_ignore_ascii_case("bl");
            let target = u64::from_str_radix(&c[2], 16).unwrap_or(0);
            if is_bl {
                if let Some((_, name)) = resolve(target) {
                    let cname = canon(&name);
                    if let Some(&(dst_arg, size_arg)) = copy_tbl.get(cname) {
                        let dst = regs.get(dst_arg).copied().flatten();
                        if let Some(off) = dst {
                            sites.push(Site {
                                off: off as u64,
                                size: size_arg.and_then(|a| imms[a]),
                                callee: cname.to_string(),
                                kind: 'a',
                                idx,
                            });
                        }
                    }
                    if cname == "import_iovec" || cname == "__io_import_iovec" {
                        // array comes through x4 = &iov; the slot holds its address
                        if let Some(slot) = regs.get(4).copied().flatten() {
                            if let Some(arr) = slots.get(&slot) {
                                let size = imms[3].map(|n| n * 16);
                                sites.push(Site {
                                    off: *arr as u64,
                                    size,
                                    callee: cname.to_string(),
                                    kind: 'a',
                                    idx,
                                });
                            }
                        }
                    }
                }
                branches.push((target, false));
                for r in 0..=18 {
                    regs[r] = None;
                    imms[r] = None;
                }
            } else {
                branches.push((target, true));
            }
            continue;
        }

        // --- default: invalidate a written destination register ---
        const NON_WRITING: &[&str] = &[
            "cmp", "cmn", "tst", "ccmp", "ccmn", "b", "br", "blr", "ret", "cbz", "cbnz",
            "tbz", "tbnz", "nop", "paciasp", "autiasp", "bti", "hint", "dmb", "dsb", "isb",
            "wfe", "wfi", "sevl", "svc", "prfm", "bl",
        ];
        if NON_WRITING.contains(&m.as_str()) || m.starts_with("b.") {
            // Constants are cleared at every branch: a value materialized on
            // one path (e.g. mov w2, #-EINVAL) must not leak into a later
            // block's call attribution. Pointer provenance (regs) is kept as a
            // may-fact across branches.
            if m.starts_with('b') || m.starts_with("cb") || m.starts_with("tb") || m == "br" || m == "blr"
            {
                imms = [None; 31];
            }
            continue;
        }
        // ldp writes two registers; capture both
        if m == "ldp" || m == "ldpsw" {
            for tok in ops.iter().take(2) {
                if let Some(r) = reg_index(tok) {
                    regs[r] = None;
                    imms[r] = None;
                }
            }
            continue;
        }
        if let Some(tok) = ops.first() {
            if let Some(r) = reg_index(tok) {
                regs[r] = None;
                imms[r] = None;
            }
        }
    }

    // dedupe
    let mut seen = std::collections::HashSet::new();
    sites.retain(|s| seen.insert((s.kind, s.off, s.callee.clone(), s.size)));
    (branches, sites, store_marks)
}

fn main() {
    let mut args = std::env::args().skip(1);
    let path = args.next().expect("usage: copy_scan <image> [wait_depth_hex]");
    let wait_depth: i64 = args
        .next()
        .map(|s| i64::from_str_radix(s.trim_start_matches("0x"), 16).expect("hex depth"))
        .unwrap_or(0x1c0);

    let boot = BootImage::load(Path::new(&path)).expect("load image");
    let btf_at = boot.embedded_btf_at();
    let btf_pair = btf_at.as_ref().map(|(offset, blob)| (*offset, blob.len()));
    let ks = kallsyms_finder::recover(&boot.kernel, btf_pair).expect("kallsyms");
    let base = kallsyms::unique(&ks.symbols, "_text")
        .or_else(|| kallsyms::unique(&ks.symbols, "_head"))
        .expect("base");
    let (rel, sorted) = relative_symbols(&ks.symbols, base);
    println!(
        "image {path}\nwait_depth 0x{wait_depth:x}; kallsyms {} symbols",
        ks.symbols.len()
    );

    let mut name_at: BTreeMap<u64, String> = BTreeMap::new();
    for (name, offs) in rel.iter() {
        for &o in offs.iter() {
            name_at.entry(o).or_insert_with(|| name.clone());
        }
    }
    let func_of = |t: u64| -> Option<(u64, String)> {
        let idx = sorted.partition_point(|&o| o <= t);
        if idx == 0 {
            return None;
        }
        let start = sorted[idx - 1];
        if t - start <= 0x40 {
            name_at.get(&start).map(|n| (start, n.clone()))
        } else {
            None
        }
    };

    // destination-argument table for copy helpers: name -> (dst arg, size arg)
    let copy_tbl: HashMap<String, (usize, Option<usize>)> = [
        ("_copy_from_user", (0, Some(2))),
        ("__arch_copy_from_user", (0, Some(2))),
        ("raw_copy_from_user", (0, Some(2))),
        ("copy_from_user", (0, Some(2))),
        ("__copy_from_user", (0, Some(2))),
        ("copy_struct_from_user", (0, None)),
        ("strncpy_from_user", (0, Some(2))),
        ("copy_from_user_nofault", (0, Some(2))),
        ("copy_from_sockptr", (0, Some(2))),
        ("move_addr_to_kernel", (2, None)),
        ("get_fd_set", (2, None)),
    ]
    .into_iter()
    .map(|(n, v)| (n.to_string(), v))
    .collect();

    let kernel = &boot.kernel;
    let mut info: HashMap<u64, FnInfo> = HashMap::new();
    let mut compute = |off: u64| -> FnInfo {
        let start = off as usize;
        let next = sorted.iter().find(|&&o| o > off).copied().unwrap_or(u64::MAX);
        let stop = (start + OBJDUMP_CAP).min(next as usize);
        let lines = disassemble_range(kernel, start, stop).unwrap_or_default();
        let name = name_at.get(&off).cloned().unwrap_or_default();
        let frame = first_sp_frame(&lines, &name).unwrap_or(0);
        let (edges, sites, store_marks) = scan_lines(&lines, frame, &copy_tbl, &func_of);
        FnInfo { frame, edges, sites, store_marks }
    };

    // BFS over direct-call/tail-call edges, starting only from wrappers the
    // image's sys_call_table actually wires (unwired stubs like
    // __arm64_sys_select exist as symbols and must not seed a chain).
    let mut wired: std::collections::HashSet<u64> = std::collections::HashSet::new();
    if let Some(&st) = rel.get("sys_call_table").and_then(|s| s.iter().next()) {
        for i in 0..1024usize {
            let at = st as usize + i * 8;
            if at + 8 > kernel.len() {
                break;
            }
            let v = u64::from_le_bytes(kernel[at..at + 8].try_into().unwrap());
            if v < base || v - base >= kernel.len() as u64 {
                break;
            }
            if let Some(n) = name_at.get(&(v - base)) {
                if n.starts_with("__arm64_sys_") {
                    wired.insert(v - base);
                }
            }
        }
        println!("sys_call_table: {} wired wrappers", wired.len());
    } else {
        eprintln!("sys_call_table not found -- falling back to name pattern");
    }

    let mut best_min: HashMap<u64, u64> = HashMap::new();
    let mut best_max: HashMap<u64, u64> = HashMap::new();
    let mut via: HashMap<u64, String> = HashMap::new();
    let mut queue: VecDeque<(u64, u64, u64, u32, String)> = VecDeque::new();
    let mut wrappers = 0usize;
    for (name, offs) in rel.iter() {
        if name.starts_with("__arm64_sys_") {
            for &o in offs.iter() {
                if rel.contains_key("sys_call_table") && !wired.contains(&o) {
                    continue;
                }
                wrappers += 1;
                queue.push_back((o, 0, 0, 0, name.clone()));
            }
        }
    }
    let mut pops = 0usize;
    while let Some((off, pmin, pmax, depth, via_name)) = queue.pop_front() {
        pops += 1;
        if pops > 500_000 {
            eprintln!("pop cap reached");
            break;
        }
        if !info.contains_key(&off) {
            let fi = compute(off);
            info.insert(off, fi);
        }
        let (frame, edges) = {
            let fi = &info[&off];
            (fi.frame, fi.edges.clone())
        };
        let smin = pmin + frame;
        let smax = pmax + frame;
        let improved = best_min.get(&off).map_or(true, |&b| smin < b);
        if !improved {
            best_max.insert(off, best_max.get(&off).copied().unwrap_or(0).max(smax));
            continue;
        }
        best_min.insert(off, smin);
        best_max.insert(off, best_max.get(&off).copied().unwrap_or(0).max(smax));
        via.insert(off, via_name.clone());
        if depth >= 8 {
            continue;
        }
        for &(t, is_tail) in &edges {
            if let Some((cstart, _)) = func_of(t) {
                if cstart == off {
                    continue;
                }
                if is_tail {
                    queue.push_back((
                        cstart,
                        smin.saturating_sub(frame),
                        smax.saturating_sub(frame),
                        depth + 1,
                        via_name.clone(),
                    ));
                } else {
                    queue.push_back((cstart, smin, smax, depth + 1, via_name.clone()));
                }
            }
        }
    }
    println!(
        "BFS: {wrappers} wrappers, {} functions reached, {pops} pops",
        best_min.len()
    );

    // report
    let mut rows: Vec<(i64, String)> = Vec::new();
    // [full_a, tail_a, head_a, full_b, tail_b, head_b]; 'b' rows carry an
    // assumed size and are only "an sp-pointer stored to a slot" -- a real
    // copy into that array was not necessarily seen.
    let mut counts = [0usize; 6];
    let mut n_k3clash = 0usize;
    for (off, fi) in info.iter() {
        let Some(&smin) = best_min.get(off) else { continue };
        let smax = best_max.get(off).copied().unwrap_or(smin);
        let via_name = via.get(off).cloned().unwrap_or_default();
        let fname = name_at.get(off).cloned().unwrap_or_else(|| format!("0x{off:x}"));
        for s in &fi.sites {
            let base_min = smin as i64 - s.off as i64;
            if base_min < 0x130 {
                continue;
            }
            let s_size_opt = s.size.filter(|v| *v <= 0x4000);
            let s_size = s_size_opt.unwrap_or(0x80) as i64;
            let cov = |sigma: i64| -> (i64, i64) {
                // (lowest covered byte, highest covered byte); byte index grows
                // with address, base = the array's deepest (lowest) address.
                let base_byte = wait_depth - (sigma - s.off as i64);
                (base_byte, base_byte + s_size - 8)
            };
            let (lo_a, hi_a) = cov(smin as i64);
            let (lo_b, hi_b) = cov(smax as i64);
            let verdict_of = |lo: i64, hi: i64| {
                if lo <= 0x00 && hi >= 0x57 {
                    "FULL"
                } else if lo <= 0x30 && hi >= 0x47 {
                    "TAIL"
                } else if lo <= 0x00 && hi >= 0x27 {
                    "HEAD"
                } else {
                    "-"
                }
            };
            let v1 = verdict_of(lo_a, hi_a);
            let v2 = verdict_of(lo_b, hi_b);
            let verdict = if v1 != "-" { v1 } else { v2 };
            if verdict != "-" {
                let ci = match (verdict, s.kind) {
                    ("FULL", 'a') => 0,
                    ("TAIL", 'a') => 1,
                    ("HEAD", 'a') => 2,
                    ("FULL", _) => 3,
                    ("TAIL", _) => 4,
                    ("HEAD", _) => 5,
                    _ => usize::MAX,
                };
                if ci != usize::MAX {
                    counts[ci] += 1;
                }
            }
            let tag = if s.kind == 'a' { "a " } else { "b?" };
            // K3: any other sp-relative store AFTER the copy that lands in the
            // waiter window (bytes -0x10..0x60) would clobber the stamp.
            let mut k3 = 0usize;
            let mut k3_bytes: Vec<i64> = Vec::new();
            if s.kind == 'a' {
                for (i, slot) in &fi.store_marks {
                    if *i <= s.idx {
                        continue;
                    }
                    let hit = [smin as i64, smax as i64].iter().any(|sigma| {
                        let byte = wait_depth - (sigma - *slot);
                        (-0x10..=0x60).contains(&byte)
                    });
                    if hit {
                        k3 += 1;
                        k3_bytes.push(wait_depth - (smin as i64 - *slot));
                    }
                }
                if k3 > 0 {
                    n_k3clash += 1;
                }
            }
            let k3_note = if s.kind == 'a' && k3 > 0 {
                format!(" K3CLASH={k3}@{k3_bytes:?}")
            } else {
                String::new()
            };
            let size_note = if s_size_opt.is_some() { "" } else { "*" };
            rows.push((
                base_min,
                format!(
                    "[{tag}] {fname}@i={} off=0x{:x} size={:#x}{size_note} Σ=0x{smin:x}..0x{smax:x} \
                     va={via_name} covers Σmin 0x{lo_a:x}..0x{hi_a:x} Σmax 0x{lo_b:x}..0x{hi_b:x} \
                     [{verdict}]{k3_note} {}",
                    s.idx, s.off, s_size, s.callee
                ),
            ));
        }
    }
    rows.sort_by(|a, b| b.0.cmp(&a.0));
    let total = rows.len();
    for (_, line) in rows.iter().take(120) {
        println!("site {line}");
    }
    println!(
        "sites(base>=0x130): {total}; confirmed(a): FULL={} TAIL={} HEAD={} (k3clash={n_k3clash}); \
         unconfirmed(b?, assumed 0x80): FULL={} TAIL={} HEAD={}",
        counts[0], counts[1], counts[2], counts[3], counts[4], counts[5]
    );
}
