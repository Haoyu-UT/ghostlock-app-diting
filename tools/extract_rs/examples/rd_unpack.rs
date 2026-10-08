// Throwaway diagnostic: decompress the stock/patched diting ramdisks (lz4
// legacy frames) with the extractor's reference-compatible block decoder,
// minus its MTK-kernel Image check and single-chunk break heuristic.
use std::fs;

const LZ4_LEGACY_MAGIC: [u8; 4] = [0x02, 0x21, 0x4c, 0x18];

fn decode_block(input: &[u8], max_output: usize) -> Result<Vec<u8>, String> {
    let mut out: Vec<u8> = Vec::with_capacity(input.len().min(max_output));
    let mut ip = 0usize;
    while ip < input.len() {
        let token = input[ip];
        ip += 1;
        let mut lit = (token >> 4) as usize;
        if lit == 15 {
            loop {
                if ip >= input.len() {
                    return Err("truncated literal length".into());
                }
                let b = input[ip];
                ip += 1;
                lit += b as usize;
                if b != 255 {
                    break;
                }
            }
        }
        if ip + lit > input.len() {
            return Err("truncated literals".into());
        }
        out.extend_from_slice(&input[ip..ip + lit]);
        ip += lit;
        if ip >= input.len() {
            break;
        }
        if ip + 2 > input.len() {
            return Err("truncated match offset".into());
        }
        let off = u16::from_le_bytes([input[ip], input[ip + 1]]) as usize;
        ip += 2;
        let mut mlen = (token & 0x0F) as usize + 4;
        if mlen == 19 {
            loop {
                if ip >= input.len() {
                    return Err("truncated match length".into());
                }
                let b = input[ip];
                ip += 1;
                mlen += b as usize;
                if b != 255 {
                    break;
                }
            }
        }
        if off == 0 {
            out.resize(out.len() + mlen, 0);
        } else {
            if off > out.len() {
                return Err("match before start".into());
            }
            let start = out.len() - off;
            for i in 0..mlen {
                let b = out[start + i];
                out.push(b);
            }
        }
        if out.len() > max_output {
            return Err("output bound exceeded".into());
        }
    }
    Ok(out)
}

fn decode_frame(payload: &[u8]) -> Result<Vec<u8>, String> {
    if payload.len() <= 8 || payload[..4] != LZ4_LEGACY_MAGIC {
        return Err("not an lz4 legacy frame".into());
    }
    let mut out = Vec::new();
    let mut ip = 4usize;
    while ip + 4 <= payload.len() {
        let block_len = u32::from_le_bytes(payload[ip..ip + 4].try_into().unwrap()) as usize;
        ip += 4;
        if block_len == 0 {
            break;
        }
        let end = ip + block_len;
        if end > payload.len() {
            return Err("truncated block".into());
        }
        let block_out = decode_block(&payload[ip..end], 64 << 20)?;
        ip = end;
        out.extend_from_slice(&block_out);
    }
    Ok(out)
}

fn main() {
    for (src, dst) in [
        ("/tmp/rd-stock.lz4", "/tmp/rd-stock.cpio"),
        ("/tmp/rd-patched.lz4", "/tmp/rd-patched.cpio"),
    ] {
        let payload = fs::read(src).unwrap();
        let out = decode_frame(&payload).expect("ramdisk decode");
        println!("{src}: {} -> {} bytes", payload.len(), out.len());
        fs::write(dst, &out).unwrap();
    }
}
