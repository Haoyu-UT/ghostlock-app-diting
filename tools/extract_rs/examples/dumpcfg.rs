//! Temporary helper: dump the IKCONFIG text embedded in a kernel image.
//!
//! usage: dumpcfg <image>

use std::path::Path;

use ghostlock_extract::boot::BootImage;
use ghostlock_extract::ikconfig::KernelConfig;

fn main() {
    let path = std::env::args().nth(1).expect("usage: dumpcfg <image>");
    let boot = BootImage::load(Path::new(&path)).expect("load image");
    match KernelConfig::from_image(&boot.kernel) {
        Ok(cfg) => print!("{}", cfg.text()),
        Err(err) => {
            eprintln!("no config: {err}");
            std::process::exit(1);
        }
    }
}
