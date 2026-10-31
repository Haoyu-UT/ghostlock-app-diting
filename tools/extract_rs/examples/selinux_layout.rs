//! Throwaway diagnostic (local-only): dump the `selinux_state` BTF layout.
//!
//! usage: cargo run --release --example selinux_layout -- <image>...

use ghostlock_extract::boot::BootImage;
use ghostlock_extract::btf::Btf;
use std::path::Path;

fn main() {
    for path in std::env::args().skip(1) {
        println!("### {path}");
        let boot = match BootImage::load(Path::new(&path)) {
            Ok(boot) => boot,
            Err(error) => {
                println!("load failed: {error:?}");
                continue;
            }
        };
        let Some((_, blob)) = boot.embedded_btf_at() else {
            println!("no embedded BTF");
            continue;
        };
        let btf = match Btf::new(&blob) {
            Ok(btf) => btf,
            Err(error) => {
                println!("btf parse failed: {error:?}");
                continue;
            }
        };
        println!("sizeof(selinux_state) = {:?}", btf.size("selinux_state"));
        for field in [
            "disabled",
            "enforcing",
            "checkreqprot",
            "initialized",
            "policycap",
            "android_netlink_route",
            "status_page",
            "avc",
            "policy",
            "policy_mutex",
        ] {
            println!(
                "selinux_state.{field} = {:?} (type size {:?})",
                btf.field("selinux_state", field),
                btf.direct_field_size("selinux_state", field)
            );
        }
    }
}
