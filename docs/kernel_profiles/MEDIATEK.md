# Running GhostLock on a MediaTek device

> 中文版: [MEDIATEK_ZH.md](MEDIATEK_ZH.md)

This guide is for MediaTek users who extract the offsets by themselves but have not yet obtained a working run. If
the device is listed with an exact `uname -r` match and runs, this guide does
not apply.

MediaTek kernels require two physical addresses that the kernel `Image` does not carry: `kernel_phys_load` (the
kernel's physical load address) and `kernel_phys_offset` (the DRAM base, i.e. the
linear map's `PHYS_OFFSET`). When they are missing or incorrect, the attack
fails during W1: it is retried to its limit and then fails.

```
[*] W1 attempt 1/15
...
[*] W1 attempt 15/15
[-] Write 1 failed
```

Both values live in the device's own `vendor_boot.img`, so **normally no root is
needed**:

| value | source |
|---|---|
| `kernel_phys_load` | the header's `kernel_addr` field |
| `kernel_phys_offset` | the `/memory` node of the DTB in the header's `dtb` section |

On MediaTek the `dtb` section is a DTBO table (the `dtbo.img` format); the
extractor reads it directly. If a particular image has `dtb_size = 0` — the
bootloader takes the DTB from elsewhere — supply the phone's `dtbo.img` with
`--dtbo` (command below); it carries the same `/memory` node.

## Step 1 — extract from `boot.img` + `vendor_boot.img`

### In the app

Start a parse and choose the phone's `boot.img`. On a MediaTek device the app
then asks for `vendor_boot.img` (recommended) — attach it. If the `vendor_boot`
carries no usable `/memory` (or you skip it), the app asks for `dtbo.img` next.
The parsed profile then contains both physical values if either image supplied
them; finish the parse flow as usual. Skipping both leaves
`kernel_phys_offset` empty, and the run fails at W1.

### On a PC

```sh
ghostlock-extract boot.img --vendor-boot vendor_boot.img \
    --iomem /dev/null --format conf --out profile.conf
```

`--iomem /dev/null` matters on a PC: without it the tool reads the **build
host's** `/proc/iomem` and silently produces a plausible wrong pair.

If the image carries no DTB, add the phone's `dtbo.img`:

```sh
ghostlock-extract boot.img --vendor-boot vendor_boot.img --dtbo dtbo.img \
    --iomem /dev/null --format conf --out profile.conf
```

The tool prints which source it used:

```
info: vendor_boot; kernel_phys_load=0x40000000
info: vendor_boot DTB /memory; kernel_phys_offset=0x40000000
```

## Step 2 — rooted fallback (no usable images)

If you do not have the firmware images, or neither the `vendor_boot` nor a
`dtbo.img` carries a DTB, read the two values from the running device instead.
`/proc/iomem` and `/proc/kallsyms` are readable only by root, so the device must
give you a root shell (`adb root` on a userdebug/eng build, or an equivalent
root). No manager app is needed.

Do **not** use KernelSU, ReSukiSU, or KowSU, including the form that patches the
kernel: a KernelSU-patched kernel interferes with the exploit. The script checks
root and KernelSU for you and stops with a message if either is not satisfied.

`tools/mtk-phys/` reads the device and prints both values in coloured text.
Pick the section for your setup.

### Android (on the phone)

If `mtk-phys.sh` is already on the phone, run it from a root shell (a terminal
app with `su`):

```sh
su -c 'sh /data/local/tmp/mtk-phys.sh'
```

If it is not on the phone, use the entry for your computer below instead.

### Windows (on your PC)

`adb` must be on PATH and the phone connected.

```bat
tools\mtk-phys\extract_phys.bat
```

### macOS / Linux (on your PC)

`adb` must be on PATH and the phone connected.

```sh
tools/mtk-phys/extract_phys.sh
```

If more than one device is connected, select one first: `set ANDROID_SERIAL=<serial>`
on Windows, or prefix the command with `ANDROID_SERIAL=<serial>` on macOS/Linux.

## Step 3 — copy the script output into the app

When the script finishes, it prints the two values:

```
kernel_phys_load = <value>
kernel_phys_offset = <value>
```

Open the app's **Advanced parameter overrides** page and set the two fields to
those values. Saving applies them to the next run; no rebuild is required.

## Step 4 — run and verify

Run the exploit once, then read the first lines of the debug log
(`Download/ghostlock-debug-log/<time>/*.log.txt`):

```
[*] soc: mtk; kernel_phys_load=<value>
[+] p0 profile ... phys_offset=<value> kernel_phys_load=<value>
```

If W1 keeps failing, one of the values is still incorrect; recheck the source
output (or re-extract with the matching `vendor_boot.img`).

## Adding the device as a built-in (maintainers)

To ship a built-in profile for this kernel, follow [README.md](README.md) and
run the extractor with the device's `boot.img` plus its `vendor_boot.img`:

```sh
ghostlock-extract boot.img --vendor-boot vendor_boot.img \
    --iomem /dev/null --format conf --out profile.conf
```

The extractor now emits **both** physical values from those images (adding
`--dtbo` when the `vendor_boot` has no DTB). Prefer the image's embedded
kallsyms; do not pass a device `/proc/kallsyms`. Only when no image carries a
DTB does `kernel_phys_offset` need `--iomem` (a rooted device dump) or a
hand-filled value, and `kernel_phys_load` can come from `--phys`.
