// SPDX-License-Identifier: Apache-2.0
//! `vm up`, `vm run` and `vm probe` — disposable VMs, never the host kernel (`I-12`).
//!
//! The mechanism, measured on 2026-09-06 (`F0.VM.01`): a distribution cloud image
//! boots its own kernel under plain `qemu`, a throwaway qcow2 overlay keeps the
//! base pristine so every run is a restore from snapshot, and a `NoCloud` seed ISO
//! carries the commands to run. No `sudo`, no kernel build, no host rootfs
//! mounted into the guest. The distro kernels cover the matrix: 20.04→5.4,
//! Debian 11→5.10, 22.04→5.15, Debian 12→6.1, 24.04→6.8, 26.04→7.0.
//!
//! `vm probe` is where `F0.VER.16` and `F0.VER.19` live: both load a BPF program,
//! which needs root the host does not grant and which `I-12` forbids there anyway.

use crate::SKIP;
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

/// A catalogued image. Only `ubuntu-24.04` is measured so far; the rest boot the
/// same way or fail visibly at boot — this command reports what happens.
struct Image {
    name: &'static str,
    url: &'static str,
    /// The kernel the plan's matrix expects from it (§F0.VM.02), as the
    /// summary prints it.
    expect: &'static str,
    /// The tiers `expect` names, machine-readable — the column headed
    /// `result` compares the *measured* tier against this list, so a row
    /// that disagrees with the plan is a FAIL and not a note for a reader
    /// to notice. Several entries where the plan itself allows a range
    /// (6.8 is L2 on Ubuntu and L3 on Fedora, by LSM policy, not version).
    /// `expect` and this list are checked to agree by a unit test.
    tiers: &'static [&'static str],
}

const IMAGES: &[Image] = &[
    Image { name: "ubuntu-20.04", url: "https://cloud-images.ubuntu.com/focal/current/focal-server-cloudimg-amd64.img", expect: "5.4 (L1)", tiers: &["L1"] },
    Image { name: "debian-11", url: "https://cloud.debian.org/images/cloud/bullseye/latest/debian-11-genericcloud-amd64.qcow2", expect: "5.10 (L2-)", tiers: &["L2-"] },
    Image { name: "ubuntu-22.04", url: "https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img", expect: "5.15 (L2)", tiers: &["L2"] },
    Image { name: "debian-12", url: "https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.qcow2", expect: "6.1 (L3)", tiers: &["L3"] },
    Image { name: "ubuntu-24.04", url: "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img", expect: "6.8 (L2/L3)", tiers: &["L2", "L3"] },
    Image { name: "fedora-40", url: "https://archives.fedoraproject.org/pub/archive/fedora/linux/releases/40/Cloud/x86_64/images/Fedora-Cloud-Base-Generic.x86_64-40-1.14.qcow2", expect: "6.8 (L3)", tiers: &["L3"] },
    Image { name: "ubuntu-26.04", url: "https://cloud-images.ubuntu.com/resolute/current/resolute-server-cloudimg-amd64.img", expect: "7.0 (L2/L3, Landlock audit)", tiers: &["L2", "L3"] },
];

const DIR: &str = "vm/images";

/// The product's own BPF object (`F2.WS.01`). Compiling it proves nothing about
/// whether a kernel will accept it — the verifier is a separate judge, and its
/// answer differs per kernel — so `vm probe` loads it on every matrix image.
const PRODUCT_OBJ: &str = "crates/aisme-ebpf/target/bpfel-unknown-none/release/aisme-ebpf";
/// The verification probe object, built by `build-ebpf` alongside the product crate.
const PROBE_OBJ: &str = "tests/probes/ebpf/target/bpfel-unknown-none/release/aisme-ebpf-verify";
/// A static `bpftool` for the WSL2 guests, fetched once from libbpf's releases.
/// The cloud images keep their own kernel-matched package; a WSL2 guest has
/// none (`linux-tools-<microsoft release>` does not exist), and installing the
/// generic one through `apt` is the one first-time action the guest performs —
/// the common factor of every interop loss measured in a non-systemd guest.
const BPFTOOL_URL: &str =
    "https://github.com/libbpf/bpftool/releases/download/v7.6.0/bpftool-v7.6.0-amd64.tar.gz";
const BPFTOOL_BIN: &str = "vm/images/bpftool";

pub(crate) fn run(name: &str, args: &[&str]) -> u8 {
    for tool in ["qemu-system-x86_64", "qemu-img", "genisoimage"] {
        if !have(tool) {
            eprintln!("skip: {tool} is not installed; `cargo xtask doctor` names the package.");
            return SKIP;
        }
    }
    // `vm probe --all` walks the catalogue: one boot per image, the tier line of
    // each, and a table at the end — the "reports the tier and Landlock ABI per
    // kernel" that GATE F0 asks for.
    if name == "vm probe" && args.first() == Some(&"--all") {
        return probe_all();
    }
    let Some((&image_name, rest)) = args.split_first() else {
        eprintln!("usage: cargo xtask {name} <image> [-- command]");
        eprintln!(
            "images: {}",
            IMAGES.iter().map(|i| i.name).collect::<Vec<_>>().join(", ")
        );
        return 1;
    };
    if let Some(variant) = image_name.strip_prefix("wsl2-") {
        return wsl2(name, variant, rest);
    }
    let Some(image) = IMAGES.iter().find(|i| i.name == image_name) else {
        eprintln!("error: unknown image `{image_name}`; see `cargo xtask vm up` for the list.");
        return 1;
    };
    match name {
        "vm up" => up(image),
        "vm run" => {
            let with_dist = rest.contains(&"--with-dist");
            let cmd = rest
                .iter()
                .filter(|a| **a != "--with-dist")
                .skip_while(|a| **a == "--")
                .copied()
                .collect::<Vec<_>>()
                .join(" ");
            if cmd.is_empty() {
                eprintln!("usage: cargo xtask vm run <image> [--with-dist] -- <command>");
                return 1;
            }
            let staged = if with_dist {
                match build_dist_static() {
                    Ok(v) => {
                        println!("staged for {} ({STAGE_TARGET}, crt-static):", image.name);
                        for f in &v {
                            println!("  {:<20} {:>9} B  {}", f.name, f.size, &f.sha256[..16]);
                        }
                        v
                    }
                    Err(e) => {
                        eprintln!("FAIL vm run --with-dist: {e}");
                        return 1;
                    }
                }
            } else {
                Vec::new()
            };
            let prologue = if staged.is_empty() {
                String::new()
            } else {
                install_script(&staged)
            };
            let body = guarded(&prologue, &cmd);
            boot_with(
                image,
                &format!("echo \"=====AISME-BEGIN=====\"\n{body}\necho \"=====AISME-END=====\""),
                "run",
                &staged,
            )
        }
        _ => probe(image),
    }
}

/// Fetch the base image once and create a fresh overlay. The base is never
/// written: the overlay is what boots, and it is recreated every time.
fn up(image: &Image) -> u8 {
    std::fs::create_dir_all(DIR).ok();
    let base = base_path(image);
    if !base.is_file() {
        println!("fetching {} …", image.url);
        let ok = Command::new("curl")
            .args(["-fsSL", "-o"])
            .arg(&base)
            .arg(image.url)
            .status();
        // `-f` makes curl fail on an HTTP error instead of saving the error page as
        // the image — a 404 body once reached `qemu-img create` before anything said
        // so. The format check is the second line of defence for the same reason.
        if !ok.is_ok_and(|s| s.success()) || !is_qcow2(&base) {
            eprintln!(
                "skip: {} did not yield a qcow2 image (HTTP error or wrong format)",
                image.url
            );
            let _ = std::fs::remove_file(&base);
            return SKIP;
        }
    }
    match fresh_overlay(image) {
        Ok(overlay) => {
            println!(
                "PASS vm up {}: base {} · overlay {} (fresh) · expects kernel {}",
                image.name,
                base.display(),
                overlay.display(),
                image.expect
            );
            0
        }
        Err(e) => {
            eprintln!("FAIL vm up {}: {e}", image.name);
            1
        }
    }
}

/// `qemu-img info` is the authority on what a file is; a byte count is not.
fn is_qcow2(path: &Path) -> bool {
    Command::new("qemu-img")
        .args(["info", "--output=json"])
        .arg(path)
        .output()
        .is_ok_and(|o| {
            o.status.success()
                && String::from_utf8_lossy(&o.stdout).contains("\"format\": \"qcow2\"")
        })
}

fn base_path(image: &Image) -> PathBuf {
    Path::new(DIR).join(format!("{}.img", image.name))
}

fn fresh_overlay(image: &Image) -> Result<PathBuf, String> {
    let base = base_path(image);
    let overlay = Path::new(DIR).join(format!("{}.overlay.qcow2", image.name));
    let _ = std::fs::remove_file(&overlay);
    let st = Command::new("qemu-img")
        .args(["create", "-q", "-f", "qcow2", "-b"])
        .arg(base.canonicalize().map_err(|e| e.to_string())?)
        .args(["-F", "qcow2"])
        .arg(&overlay)
        .arg("8G")
        .status()
        .map_err(|e| e.to_string())?;
    st.success()
        .then_some(overlay)
        .ok_or_else(|| "qemu-img create failed".into())
}

/// Every catalogued image in turn; a failing image does not stop the others.
fn probe_all() -> u8 {
    let mut rows = Vec::new();
    let mut worst = 0;
    for image in IMAGES {
        println!("═══ {} (expects {})", image.name, image.expect);
        let code = probe(image);
        worst = worst.max(code);
        let log = std::fs::read_to_string(Path::new(DIR).join(format!("{}.probe.log", image.name)))
            .unwrap_or_default();
        let field = |key: &str| {
            log.lines()
                .map(strip_ansi)
                .find_map(|l| l.strip_prefix(key).map(|v| v.trim().to_owned()))
                .unwrap_or_else(|| "?".to_owned())
        };
        rows.push((
            image.name,
            field("kernel:"),
            field("landlock_abi:"),
            field("tier:"),
            image.expect,
            image.tiers,
            code,
        ));
    }
    println!(
        "\n{:<14} {:<22} {:<12} {:<5} {:<30} result",
        "image", "kernel", "ABI", "tier", "plan expects"
    );
    for (n, k, a, t, e, x, c) in &rows {
        // PASS is the conjunction, not the exit code. The guest exiting 0
        // says the probe ran; it says nothing about whether what it measured
        // is what the plan expects, and this column is headed `result` right
        // beside `plan expects`, so reading it as agreement is the natural
        // reading. It was not one until the tier comparison below existed.
        let agrees = x.contains(&t.as_str());
        println!(
            "{n:<14} {k:<22} {a:<12} {t:<5} {e:<30} {}",
            match (*c == 0, agrees) {
                (true, true) => "PASS",
                (true, false) => "FAIL tier",
                (false, _) => "FAIL",
            }
        );
        if *c == 0 && !agrees {
            worst = worst.max(1);
        }
    }
    worst
}

/// The capability probe plus, when the object exists, the two BPF rows. Output is
/// the guest's own, between markers, so nothing here is inferred.
fn probe(image: &Image) -> u8 {
    let mut script = String::from(TIER_PROBE);
    script.push_str(TRACEPOINT_FORMAT_PROBE);
    if Path::new(PROBE_OBJ).is_file() {
        script.push_str(BPF_PROBE);
    } else {
        script.push_str("echo \"bpf probes: object absent; run `cargo xtask build-ebpf` first\"\n");
    }
    script.push_str("echo \"=====AISME-END=====\"\n");
    boot(image, &script, "probe")
}

/// The guest script writes to `/dev/console`, not `/dev/ttyS0`: every cloud image
/// here boots with `console=ttyS0` last on its command line, so `/dev/console`
/// resolves to the serial port qemu captures — and it does so on Debian too,
/// where a serial getty owns `/dev/ttyS0` and writes to the device by name
/// never reached the log (measured on Debian 12, 2026-09-06).
///
/// Write the `NoCloud` seed, boot under KVM when available (TCG otherwise, said
/// aloud), wait for the guest to power itself off, print the marked output.
fn boot(image: &Image, script: &str, what: &str) -> u8 {
    boot_with(image, script, what, &[])
}

/// `boot`, plus files staged into the seed ISO beside the script.
fn boot_with(image: &Image, script: &str, what: &str, staged: &[Staged]) -> u8 {
    if !base_path(image).is_file() {
        let code = up(image);
        if code != 0 {
            return code;
        }
    }
    let overlay = match fresh_overlay(image) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("FAIL: {e}");
            return 1;
        }
    };
    let seed = match write_seed(image, script, staged) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("FAIL: seed: {e}");
            return 1;
        }
    };
    let kvm = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
        .is_ok();
    if !kvm {
        eprintln!(
            "note: /dev/kvm not writable in this session; booting under TCG (slow, correct)."
        );
    }
    let log = Path::new(DIR).join(format!("{}.{what}.log", image.name));
    let logfile = match std::fs::File::create(&log) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("FAIL: cannot create {}: {e}", log.display());
            return 1;
        }
    };
    let mut cmd = Command::new("timeout");
    cmd.arg("900").arg("qemu-system-x86_64");
    if kvm {
        cmd.args(["-enable-kvm", "-cpu", "host"]);
    } else {
        cmd.args(["-accel", "tcg", "-cpu", "max"]);
    }
    cmd.args(["-m", "2048", "-smp", "2", "-nographic", "-no-reboot"])
        .arg("-drive")
        .arg(format!("file={},format=qcow2,if=virtio", overlay.display()))
        .arg("-drive")
        .arg(format!(
            "file={},format=raw,if=virtio,media=cdrom,readonly=on",
            seed.display()
        ))
        .args([
            "-netdev",
            "user,id=n0",
            "-device",
            "virtio-net-pci,netdev=n0",
        ])
        .stdout(
            logfile
                .try_clone()
                .ok()
                .map_or(std::process::Stdio::null(), std::process::Stdio::from),
        )
        .stderr(logfile);
    println!(
        "booting {} ({}) …",
        image.name,
        if kvm { "KVM" } else { "TCG" }
    );
    let status = cmd.status();
    let text = std::fs::read_to_string(&log).unwrap_or_default();
    let (Some(a), Some(b)) = (
        text.find("=====AISME-BEGIN====="),
        text.find("=====AISME-END====="),
    ) else {
        eprintln!(
            "FAIL vm {what} {}: markers missing; qemu {:?}; see {}",
            image.name,
            status.ok(),
            log.display()
        );
        return 1;
    };
    let body = &text[a..b];
    for line in body.lines().skip(1) {
        println!("  {}", strip_ansi(line));
    }
    println!(
        "PASS vm {what} {} — output above is the guest's; log {}",
        image.name,
        log.display()
    );
    0
}

/// The target the staged build uses: `x86_64-unknown-linux-gnu` with
/// `crt-static`, **not** the default dynamic build, and the reason is measured.
/// This host's glibc is 2.43; every guest's is older — 2.31 on Ubuntu 20.04 and
/// Debian 11 — and glibc symbol versioning is forward-only, so a dynamically
/// linked binary built here fails on every image in the matrix. Point 12 of
/// `docs/05` specified the transport and did not see this: the seed ISO carries
/// the files fine, they just would not run.
///
/// musl would also solve it and costs an owner action (`rustup target add` plus
/// `musl-tools`, because mimalloc compiles C). `crt-static` needs neither, and
/// was measured to produce a 1.65 MB static-pie binary with no glibc version
/// references at all — well under §2.22's 12 MB ceiling — which then ran on the
/// 5.4 guest.
const STAGE_TARGET: &str = "x86_64-unknown-linux-gnu";

/// Build the product binaries statically and hash what will be staged.
fn build_dist_static() -> Result<Vec<Staged>, String> {
    let st = Command::new("cargo")
        .args([
            "build",
            "--release",
            "--workspace",
            "--target",
            STAGE_TARGET,
        ])
        .env("RUSTFLAGS", "-C target-feature=+crt-static")
        .status()
        .map_err(|e| format!("cargo: {e}"))?;
    if !st.success() {
        return Err("the static build failed; its output is above".to_owned());
    }
    let dir = Path::new("target").join(STAGE_TARGET).join("release");
    let mut out = Vec::new();
    for name in crate::tooling::bin_targets().unwrap_or_default() {
        // `xtask` is the host's build tool, not a product binary. Staging it
        // would ship megabytes of ISO the guest can never use and imply it is
        // part of what AISME installs.
        if name == "xtask" {
            continue;
        }
        let path = dir.join(&name);
        if !path.is_file() {
            continue;
        }
        let bytes = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        out.push(Staged {
            name,
            sha256: format!("{:x}", hasher.finalize()),
            size: bytes.len() as u64,
            path,
        });
    }
    if out.is_empty() {
        return Err("the static build produced no binaries".to_owned());
    }
    Ok(out)
}

/// The guest-side prologue: install what was staged, verify every byte, and
/// leave `$BAD` set so the caller can actually refuse.
///
/// The install root is `${AISME_ROOT:-/usr/lib/aisme}` so a unit test can run
/// this exact script against a temporary directory. A guard only ever exercised
/// in a VM is a guard nobody has seen work — and the first version of this one
/// printed "refusing to run" and then ran the command anyway, which is worse
/// than no guard because a mismatch looks handled.
fn install_script(staged: &[Staged]) -> String {
    let mut s = String::from(
        "AISME_ROOT=${AISME_ROOT:-/usr/lib/aisme}\n\
         mkdir -p \"$AISME_ROOT\"\n\
         echo \"--- staged binaries\"\n\
         BAD=0\n",
    );
    for f in staged {
        // Copied by name, never by glob: `cp /opt/aisme/aisme-*` silently
        // missed the CLI, which is called `aisme`, and only the hash check
        // below surfaced it, as `guest=missing`.
        let _ = writeln!(
            s,
            "cp \"/opt/aisme/{n}\" \"$AISME_ROOT/{n}\" 2>/dev/null; \
             chmod +x \"$AISME_ROOT/{n}\" 2>/dev/null\n\
             H=$(sha256sum \"$AISME_ROOT/{n}\" 2>/dev/null | cut -d\" \" -f1)\n\
             if [ \"$H\" = \"{h}\" ]; then echo \"  {n}: ok {short}\"; \
             else echo \"  {n}: HASH MISMATCH host={h} guest=${{H:-missing}}\"; BAD=1; fi",
            n = f.name,
            h = f.sha256,
            short = &f.sha256[..12]
        );
    }
    s
}

/// The command, run only when every staged byte matched.
fn guarded(prologue: &str, cmd: &str) -> String {
    if prologue.is_empty() {
        return cmd.to_owned();
    }
    format!(
        "{prologue}if [ \"$BAD\" = 0 ]; then\n{cmd}\nelse\n\
         echo \"refusing to run: a staged binary does not match the manifest\"\n\
         false\nfi\n"
    )
}

/// One file the host built and the guest will run, with the hash that ties the
/// two together. §2.22's reference-trace rule applied to binaries: a figure
/// that cannot name the build that produced it is not a measurement.
struct Staged {
    /// Basename in `/opt/aisme/` and in the manifest.
    name: String,
    /// Where the host built it.
    path: PathBuf,
    /// Lowercase hex sha256 of the bytes staged.
    sha256: String,
    /// Bytes.
    size: u64,
}

fn write_seed(image: &Image, script: &str, staged: &[Staged]) -> Result<PathBuf, String> {
    let dir = Path::new(DIR).join(format!("seed-{}", image.name));
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    std::fs::write(
        dir.join("meta-data"),
        format!(
            "instance-id: aisme-{}\nlocal-hostname: aisme-vm\n",
            image.name
        ),
    )
    .map_err(|e| e.to_string())?;
    let mut files = String::new();
    if Path::new(PROBE_OBJ).is_file() {
        let bytes = std::fs::read(PROBE_OBJ).map_err(|e| e.to_string())?;
        let _ = writeln!(
            files,
            "  - path: /root/probe.o\n    encoding: b64\n    content: {}",
            base64(&bytes)
        );
    }
    if Path::new(PRODUCT_OBJ).is_file() {
        let bytes = std::fs::read(PRODUCT_OBJ).map_err(|e| e.to_string())?;
        let _ = writeln!(
            files,
            "  - path: /root/aisme.o\n    encoding: b64\n    content: {}",
            base64(&bytes)
        );
    }
    for f in staged {
        let bytes = std::fs::read(&f.path).map_err(|e| format!("{}: {e}", f.path.display()))?;
        let _ = writeln!(
            files,
            "  - path: /opt/aisme/{}\n    permissions: '0755'\n    encoding: b64\n    content: {}",
            f.name,
            base64(&bytes)
        );
    }
    if !staged.is_empty() {
        // Both sides can name what ran. The guest re-hashes and refuses on a
        // mismatch, so a figure can never be attributed to a build nobody can
        // identify (§2.22's reference-trace rule).
        let mut manifest = String::from("# Written by `cargo xtask vm run --with-dist`.\n");
        for f in staged {
            let _ = writeln!(
                manifest,
                "[[binary]]\nname = \"{}\"\nsha256 = \"{}\"\nsize = {}\n",
                f.name, f.sha256, f.size
            );
        }
        let _ = writeln!(
            files,
            "  - path: /opt/aisme/manifest.toml\n    encoding: b64\n    content: {}",
            base64(manifest.as_bytes())
        );
    }
    let mut indented = String::new();
    for l in script.lines() {
        indented.push_str("      ");
        indented.push_str(l);
        indented.push('\n');
    }
    let user_data = format!(
        "#cloud-config\nwrite_files:\n{files}  - path: /root/run.sh\n    permissions: '0755'\n    content: |\n      #!/bin/bash\n      exec > /dev/console 2>&1\n      echo \"=====AISME-BEGIN=====\"\n{indented}      poweroff\nruncmd:\n  - [ /root/run.sh ]\n"
    );
    std::fs::write(dir.join("user-data"), user_data).map_err(|e| e.to_string())?;
    let iso = Path::new(DIR).join(format!("seed-{}.iso", image.name));
    let st = Command::new("genisoimage")
        .args(["-quiet", "-output"])
        .arg(&iso)
        .args(["-volid", "cidata", "-joliet", "-rock"])
        .arg(dir.join("user-data"))
        .arg(dir.join("meta-data"))
        .status()
        .map_err(|e| e.to_string())?;
    st.success()
        .then_some(iso)
        .ok_or_else(|| "genisoimage failed".into())
}

/// Reports the facts the tier is decided from (§2.17), then the tier itself.
const TIER_PROBE: &str = r#"echo "kernel: $(uname -r)"
# securityfs is not mounted on stock WSL2, and an unreadable list read as "no
# LSM" would report L1 for a kernel that enforces Landlock (F0.WSL.01). Mount it;
# if that fails, the compiled-in CONFIG_LSM is the next best evidence.
mountpoint -q /sys/kernel/security 2>/dev/null || mount -t securityfs none /sys/kernel/security 2>/dev/null
echo "lsm: $(cat /sys/kernel/security/lsm 2>/dev/null || echo unreadable)"
python3 - <<'PY'
import ctypes, gzip, os
libc = ctypes.CDLL(None, use_errno=True); libc.syscall.restype = ctypes.c_long
abi = libc.syscall(ctypes.c_long(444), None, ctypes.c_size_t(0), ctypes.c_uint32(1))
cfg = gzip.open("/proc/config.gz", "rt").read() if os.path.exists("/proc/config.gz") else open("/boot/config-" + os.uname().release).read()
k = lambda key: next((l for l in cfg.splitlines() if l.startswith(key + "=")), key + " not set")
lsm = open("/sys/kernel/security/lsm").read().strip() if os.path.exists("/sys/kernel/security/lsm") else ""
if not lsm:
    m = [l for l in cfg.splitlines() if l.startswith("CONFIG_LSM=")]
    lsm = m[0].split("=",1)[1].strip('"') if m else ""
    print("lsm source: CONFIG_LSM (securityfs unavailable)")
btf = os.path.exists("/sys/kernel/btf/vmlinux")
cg2_mount = next((l.split()[1] for l in open("/proc/mounts") if l.split()[2] == "cgroup2"), None)
cg2 = cg2_mount is not None
# Annex D.1 separates L1 from L2- by what can trap a decision and what can
# hold it, not by BTF. Both are measured, never inferred from uname: the
# syscall answers for seccomp_unotify (SECCOMP_GET_NOTIF_SIZES, op 3) and the
# cgroup2 mount answers for the freezer (cgroup.freeze, kernel >= 5.2).
sizes = (ctypes.c_uint16 * 3)()
unotify = libc.syscall(ctypes.c_long(317), ctypes.c_uint(3), ctypes.c_uint(0), ctypes.byref(sizes)) == 0
# `cgroup.freeze` "exists on non-root cgroups" (kernel cgroup-v2.rst): the root
# cgroup never has it, on any kernel, so reading the mount root reports "no
# freezer" everywhere — measured on 5.4 before this was fixed. Make a child,
# ask there, remove it.
freeze = False
if cg2:
    probe_dir = os.path.join(cg2_mount, "aisme-freeze-probe")
    try:
        os.mkdir(probe_dir)
        freeze = os.path.exists(os.path.join(probe_dir, "cgroup.freeze"))
    except OSError as e:
        print("cgroup_freeze probe:", e)
    finally:
        if os.path.isdir(probe_dir):
            os.rmdir(probe_dir)
print("landlock_abi:", abi if abi > 0 else "unavailable")
for key in ("CONFIG_BPF_LSM", "CONFIG_CGROUP_BPF", "CONFIG_DEBUG_INFO_BTF", "CONFIG_LSM"): print(k(key))
print("btf_vmlinux:", "present" if btf else "absent"); print("cgroup2:", "yes" if cg2 else "no")
print("seccomp_unotify:", "yes" if unotify else "no"); print("cgroup_freeze:", "yes" if freeze else "no")
# SECCOMP_IOCTL_NOTIF_ADDFD (kernel >= 5.9) is what lets an *allow* be delivered
# as a validated descriptor (I-28); the notifier alone can only deny safely.
# Feature-tested, never version-tested: a backport makes uname wrong in one
# direction and a vendor kernel in the other. A listener fd is opened with a
# filter that allows everything, then the ioctl is called with a NULL argument:
# The discrimination is EFAULT vs EINVAL, measured rather than assumed: seccomp's
# notify ioctl handler answers an unknown command with EINVAL from its switch's
# default arm — not with ENOTTY, which is what a file with no ioctl handler at
# all would give. A kernel that has ADDFD reaches copy_from_user and answers
# EFAULT for the NULL argument. Measured 2026-09-07: 5.4 EINVAL, 5.10 EFAULT.
addfd = False
try:
    libc.prctl(38, 1, 0, 0, 0)  # PR_SET_NO_NEW_PRIVS, required without CAP_SYS_ADMIN
    class SockFilter(ctypes.Structure):
        _fields_ = [("code", ctypes.c_uint16), ("jt", ctypes.c_uint8), ("jf", ctypes.c_uint8), ("k", ctypes.c_uint32)]
    class SockFprog(ctypes.Structure):
        _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.POINTER(SockFilter))]
    insns = (SockFilter * 1)(SockFilter(0x06, 0, 0, 0x7fff0000))  # BPF_RET|BPF_K, SECCOMP_RET_ALLOW
    prog = SockFprog(1, insns)
    listener = libc.syscall(ctypes.c_long(317), ctypes.c_uint(1), ctypes.c_uint(1 << 3), ctypes.byref(prog))
    if listener >= 0:
        ctypes.set_errno(0)
        libc.ioctl(ctypes.c_int(listener), ctypes.c_ulong(0x40182103), None)
        err = ctypes.get_errno()
        addfd = err == 14  # EFAULT: the command exists and rejected the NULL pointer
        print("seccomp_addfd probe errno:", err)
        os.close(listener)
    else:
        print("seccomp_addfd probe: listener unavailable, errno", ctypes.get_errno())
except OSError as e:
    print("seccomp_addfd probe:", e)
print("seccomp_addfd:", "yes" if addfd else "no")
# The product's rule, aisme-core::tier::tier_of, spelled the same way here so
# the matrix measures what the engine will derive (Annex D.1).
# Annex D.1's L2- promise is "every watched path decision traps" — a trap that
# can only ever answer deny is not that promise, so the boundary follows the
# capability enforcement needs (I-28, docs/05 point 13).
escalate = addfd and freeze
deny_in_kernel = abi > 0 and "landlock" in lsm and cg2
tier = "L3" if escalate and deny_in_kernel and "bpf" in lsm.split(",") else "L2" if escalate and deny_in_kernel else "L2-" if escalate else "L1"
print("tier:", tier)
PY
"#;

/// `F2.WS.01`: the `sys_enter_openat` argument offsets the tracepoint program
/// compiles in, read from the kernel that will run it.
///
/// The offsets are an ABI of the trace-event **format file**, not of a header
/// the build can check, so the program's constants are a claim about every
/// kernel in the matrix until a kernel is asked. This asks. A row that differs
/// on some kernel is a finding naming that kernel, which is why the script
/// prints what it found rather than only whether it matched.
const TRACEPOINT_FORMAT_PROBE: &str = r#"
echo "--- F2.WS.01 sys_enter_openat argument offsets"
FMT=/sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/format
[ -r "$FMT" ] || mount -t debugfs none /sys/kernel/debug 2>/dev/null
[ -r "$FMT" ] || FMT=/sys/kernel/tracing/events/syscalls/sys_enter_openat/format
if [ -r "$FMT" ]; then
  # The script does the comparison, not the reader. Three earlier versions of
  # this check produced no measurement while `vm probe` printed PASS: a printf
  # escape eaten by a layer, then field indices off by one that made awk match
  # nothing and say nothing. An empty result now prints openat_offset: NONE
  # FOUND, because a silent empty answer is the failure this row exists to
  # catch in the first place.
  #
  # Fields split on [:;]: $2 is the declaration, $4 the offset. Measured
  # against a real format file, not derived from the layout.
  awk -F'[:;]' -v n=0 '
      /field:/ {
          decl=$2; off=$4;
          sub(/.*[ *]/, "", decl);
          if (decl=="filename") { want=24 } else if (decl=="flags") { want=32 }
          else if (decl=="mode") { want=40 } else { next }
          n++;
          gsub(/[^0-9]/, "", off);
          print "  openat_offset " decl " = " off (off+0==want ? "  MATCHES" : "  DIFFERS from " want)
      }
      END { if (n==0) print "  openat_offset: NONE FOUND - the format file parsed to nothing" }
  ' "$FMT"
else
  echo "  openat_offset: format file unreadable (no debugfs and no tracefs)"
fi
"#;

/// `F0.VER.19` and `F0.VER.16`, run as root inside the guest with bpftool.
const BPF_PROBE: &str = r#"echo "--- bpftool"
export DEBIAN_FRONTEND=noninteractive
if ! command -v bpftool >/dev/null; then
  # Debian ships it as `bpftool`; Ubuntu inside linux-tools-<release>; Fedora via dnf.
  if command -v apt-get >/dev/null; then
    # An archived Debian release 404s on deb.debian.org; its packages live on
    # archive.debian.org under the same paths (measured on bullseye).
    # Cloud images start unattended-upgrades and apt-daily at boot; they hold the
    # dpkg lock for a while. Wait for it instead of racing it.
    for i in $(seq 1 60); do fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || break; sleep 2; done
    apt-get -qq update 2>&1 | tail -1
    apt-get -qq install -y bpftool 2>&1 | grep -E "^E:" | tail -1 || true
    command -v bpftool >/dev/null || apt-get -qq install -y linux-tools-common linux-tools-$(uname -r) 2>&1 | grep -E "^E:" | tail -1
    # A Microsoft (WSL2) kernel has no linux-tools-<release>; Ubuntu's wrapper then
    # refuses to run, but any versioned bpftool binary from linux-tools-generic is
    # kernel-agnostic enough for load/attach.
    if ! bpftool version >/dev/null 2>&1; then
      apt-get -qq install -y linux-tools-generic >/dev/null 2>&1
      B=$(ls /usr/lib/linux-tools/*/bpftool 2>/dev/null | head -1); [ -n "$B" ] && ln -sf "$B" /usr/local/bin/bpftool
    fi
    if ! command -v bpftool >/dev/null && grep -qs "debian.org" /etc/apt/sources.list; then
      # An archived Debian release still answers `update` on deb.debian.org but its
      # security pool has been emptied (bpftool_5.10.262-1 404s there, measured on
      # bullseye). archive.debian.org keeps both trees under the same paths.
      sed -i 's|http://deb.debian.org/debian|http://archive.debian.org/debian|g; s|http://security.debian.org/debian-security|http://archive.debian.org/debian-security|g; /-updates/d' /etc/apt/sources.list
      apt-get -qq -o Acquire::Check-Valid-Until=false update >/dev/null 2>&1
      apt-get -qq install -y bpftool 2>&1 | tail -2
    fi
  else
    dnf -q install -y bpftool >/dev/null 2>&1
  fi
fi
echo "bpftool: $(bpftool version 2>/dev/null | head -1 || echo unavailable)"
mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf
bpftool prog loadall /root/probe.o /sys/fs/bpf/probe 2>&1 && echo "loadall: OK" || echo "loadall: FAILED"

# F2.WS.01: what bpftool can and cannot say about the product's own object.
#
# It cannot say whether the verifier accepts the program, and measuring that
# here would be reading one loader's opinion as another's. `bpftool` links
# libbpf; AISME loads with `aya`, and the two disagree about the *container*
# before any instruction is examined. Measured 2026-09-07: libbpf 5.4 answers
# "failed to guess program type based on ELF section name '.text'" because it
# wants `tracepoint/<category>/<name>`, and libbpf v1.0+ on 6.8 answers
# "legacy map definitions in 'maps' section are not supported". Both are true
# of libbpf and false of aya, which parses the bare `tracepoint` section name
# (aya-obj obj.rs:327) and the legacy `maps` section (obj.rs:1073).
#
# So this row reports the container check and says plainly that the verifier
# verdict is still owed. Getting it needs the product's own loader running in
# the guest, which is `vm run --with-dist` — the gap point 12 of
# docs/05 already found in GATE F2. Printing ACCEPTED or REFUSED here would be
# a verdict this command is not entitled to give.
echo "--- F2.WS.01 aisme-ebpf object, as far as bpftool can judge it"
if [ -f /root/aisme.o ]; then
  echo "  aisme_sections: $(readelf -S /root/aisme.o 2>/dev/null | awk '/ tracepoint|maps|license/{print $2}' | tr '\n' ' ')"
  if bpftool prog loadall /root/aisme.o /sys/fs/bpf/aisme > /root/aisme.load 2>&1; then
    echo "  aisme_load: ACCEPTED by libbpf too"
    bpftool prog show pinned /sys/fs/bpf/aisme/sys_enter_openat 2>/dev/null | head -1 | sed 's/^/  /'
  elif grep -qE "legacy map definitions|guess program type" /root/aisme.load; then
    echo "  aisme_load: NOT JUDGED - libbpf cannot open an aya object; the verifier verdict is owed by vm run --with-dist"
    sed 's/^/    /' /root/aisme.load | head -3
  else
    echo "  aisme_load: REFUSED for a reason that is not a container mismatch"
    sed 's/^/    /' /root/aisme.load | head -12
  fi
else
  echo "  aisme_load: object absent; run cargo xtask build-ebpf"
fi
# Older bpftool (5.15) pins by section name, newer by program name; the program
# id from `prog show` is the same on every version, so select by id.
KR=$(bpftool prog show 2>/dev/null | awk '/ name kind_range /{sub(":","",$1); print $1; exit}')
C4=$(bpftool prog show 2>/dev/null | awk '/ name connect4 /{sub(":","",$1); print $1; exit}')
echo "--- F0.VER.19 kind_range (verifier-accepted if it has an id; xlated shows the comparison)"
[ -n "$KR" ] && bpftool prog show id "$KR" 2>&1 | head -1 || echo "kind_range: not loaded"
[ -n "$KR" ] && bpftool prog dump xlated id "$KR" 2>&1
echo "--- F0.VER.16 connect4 on a session cgroup"
# The v2 hierarchy is not always at /sys/fs/cgroup: a hybrid host (Ubuntu 20.04)
# mounts it at /sys/fs/cgroup/unified, and a directory made under the v1 tmpfs
# is not a cgroup at all ("can't open cgroup", measured). Ask /proc/mounts.
CG2=$(awk '$3=="cgroup2"{print $2; exit}' /proc/mounts)
echo "cgroup2 mount: ${CG2:-none}"
mkdir -p "$CG2/session"
[ -n "$C4" ] && bpftool cgroup attach "$CG2/session" connect4 id "$C4" 2>&1 && echo "attach: OK" || echo "attach: FAILED"
cat > /root/conn.py <<'PY'
import socket
def t(port):
    s = socket.socket(); s.settimeout(1)
    try:
        s.connect(("127.0.0.1", port)); return "connected"
    except OSError as e:
        return f"errno {e.errno} ({e.strerror})"
    finally:
        s.close()
print(f"  9998 -> {t(9998)}   9997 -> {t(9997)}")
PY
echo "inside session cgroup:"; bash -c "echo \$\$ > $CG2/session/cgroup.procs; python3 /root/conn.py"
echo "outside session cgroup:"; python3 /root/conn.py
"#;

/// `vm up|run|probe wsl2-<variant>` — a real WSL2 distribution, not a qemu guest.
///
/// WSL2 is the Windows strategy (`ADR-02`), and it is a different animal from the
/// cloud images: there is no qemu, no serial port and no seed ISO. `wsl.exe` is
/// reachable from inside a WSL2 shell through interop, so the host imports a
/// distribution from Ubuntu's official WSL rootfs tarball, sets `/etc/wsl.conf`
/// for the variant, and runs commands in it as root — output comes straight back.
///
/// Variants: `ubuntu-24.04` (systemd on, which is how `aisme run` expects to be
/// launched), `ubuntu-24.04-nosystemd` (the opt-out the plan says the daemon
/// must survive, §2.16.1) and `ubuntu-24.04-cgroupv1` (no systemd, and the
/// per-distribution `[automount] cgroups=v1` of `wsl.conf` — microsoft/WSL#13546,
/// merged 2025-10-03, which falls back to v2 when the kernel line carries
/// `cgroup_no_v1=all`). `vm probe` reports the hierarchy it found, so a WSL
/// build without that key shows up as `cgroup v1 controllers: 0` rather than as
/// a silently wrong variant.
fn wsl2(name: &str, variant: &str, rest: &[&str]) -> u8 {
    let Some(wsl) = ["wsl.exe", "/mnt/c/Windows/System32/wsl.exe"]
        .into_iter()
        .find(|w| w.contains('/') && Path::new(w).is_file() || !w.contains('/') && have(w))
    else {
        eprintln!("skip: wsl.exe is not reachable — this is not a WSL2 shell with interop (F0.WSL.02 runs on the owner's Windows machine)");
        return SKIP;
    };
    let (systemd, cgroups) = match variant {
        "ubuntu-24.04" => (true, "v2"),
        "ubuntu-24.04-nosystemd" => (false, "v2"),
        "ubuntu-24.04-cgroupv1" => (false, "v1"),
        other => {
            eprintln!(
                "error: unknown WSL2 variant `{other}`; use ubuntu-24.04, ubuntu-24.04-nosystemd or ubuntu-24.04-cgroupv1"
            );
            return 1;
        }
    };
    let distro = format!("aisme-wsl2-{variant}");
    if !registered(wsl, &distro) {
        let code = wsl2_import(wsl, &distro, variant, systemd, cgroups);
        if code != 0 || name == "vm up" {
            return code;
        }
    } else if name == "vm up" {
        println!("PASS vm up wsl2-{variant}: {distro} already registered");
        return 0;
    }
    let script = if name == "vm run" {
        let cmd = rest
            .iter()
            .skip_while(|a| **a == "--")
            .copied()
            .collect::<Vec<_>>()
            .join(" ");
        if cmd.is_empty() {
            eprintln!("usage: cargo xtask vm run wsl2-{variant} -- <command>");
            return 1;
        }
        cmd
    } else {
        wsl2_probe_script()
    };
    wsl2_exec(wsl, &distro, name, variant, systemd, &script)
}

/// Fetch Ubuntu's official WSL rootfs once, `wsl.exe --import` it, set the
/// variant's `/etc/wsl.conf`, and stop it so the setting takes effect on the next
/// start. The install directory must be a Windows path; both live under `vm/`.
fn wsl2_import(wsl: &str, distro: &str, variant: &str, systemd: bool, cgroups: &str) -> u8 {
    let tarball = Path::new(DIR).join("wsl2-ubuntu-24.04.rootfs.tar.gz");
    if !tarball.is_file() {
        println!("fetching the Ubuntu WSL rootfs …");
        let url = "https://cloud-images.ubuntu.com/wsl/releases/24.04/current/ubuntu-noble-wsl-amd64-wsl.rootfs.tar.gz";
        let ok = Command::new("curl")
            .args(["-fsSL", "-o"])
            .arg(&tarball)
            .arg(url)
            .status();
        if !ok.is_ok_and(|s| s.success()) {
            eprintln!("skip: could not fetch {url}");
            let _ = std::fs::remove_file(&tarball);
            return SKIP;
        }
    }
    // WSL will not place a distribution's VHDX inside another distribution's
    // filesystem: an install directory under this repository (which lives on
    // \\wsl.localhost\…) fails with Wsl/Service/ERROR_UNHANDLED_EXCEPTION, and
    // the same command with both paths on NTFS succeeds (measured 2026-09-06).
    // So the VHDX and the tarball go under %LOCALAPPDATA%\aisme\vm on the
    // Windows side; `wsl.exe --unregister` is how they go away.
    let Some(local) = windows_local_appdata() else {
        eprintln!("FAIL: could not resolve %LOCALAPPDATA% through interop");
        return 1;
    };
    let ntfs = Path::new(&local).join("aisme").join("vm");
    let install = ntfs.join(format!("wsl2-{variant}"));
    let ntfs_tar = ntfs.join("wsl2-ubuntu-24.04.rootfs.tar.gz");
    if std::fs::create_dir_all(&install).is_err()
        || (!ntfs_tar.is_file() && std::fs::copy(&tarball, &ntfs_tar).is_err())
    {
        eprintln!("FAIL: cannot stage under {}", ntfs.display());
        return 1;
    }
    let (Some(win_install), Some(win_tar)) = (wslpath(&install), wslpath(&ntfs_tar)) else {
        eprintln!("FAIL: wslpath could not translate the NTFS paths");
        return 1;
    };
    println!("importing {distro} …");
    // wsl.exe opens the tarball exclusively, so two imports from one tarball at
    // the same moment fail with Wsl/ERROR_SHARING_VIOLATION (measured when both
    // variants were started in parallel). Wait and retry rather than fail on it.
    let mut imported = false;
    for attempt in 1..=6 {
        let out = Command::new(wsl)
            .args(["--import", distro, &win_install, &win_tar, "--version", "2"])
            .output();
        match out {
            Ok(o) if o.status.success() => {
                imported = true;
                break;
            }
            Ok(o) => {
                let text = format!(
                    "{}{}",
                    String::from_utf8_lossy(&o.stdout),
                    String::from_utf8_lossy(&o.stderr)
                )
                .replace('\0', "");
                if text.contains("SHARING_VIOLATION") && attempt < 6 {
                    eprintln!("  tarball busy (another import running); retry {attempt}/5 in 15 s");
                    std::thread::sleep(std::time::Duration::from_secs(15));
                    continue;
                }
                for line in text.lines().filter(|l| !l.trim().is_empty()).take(3) {
                    eprintln!("  {line}");
                }
                break;
            }
            Err(e) => {
                eprintln!("  wsl.exe did not run: {e}");
                break;
            }
        }
    }
    if !imported {
        eprintln!("FAIL: wsl.exe --import {distro} failed");
        return 1;
    }
    // `cgroups=v2` is WSL's default, so the key is written only for v1: a WSL
    // build that predates it warns on unknown keys, and there is no reason to
    // provoke that for the default.
    let mut conf = format!(
        "[boot]\nsystemd={}\n",
        if systemd { "true" } else { "false" }
    );
    if cgroups == "v1" {
        conf.push_str("[automount]\ncgroups=v1\n");
    }
    // This first session runs before `wsl.conf` exists, so without systemd;
    // terminating it is harmless (see `hold_open` for why that matters).
    let _ = Command::new(wsl)
        .args(["-d", distro, "-u", "root", "--", "sh", "-c"])
        .arg(format!("printf '%s' '{conf}' > /etc/wsl.conf"))
        .status();
    let _ = Command::new(wsl).args(["--terminate", distro]).status();
    // The first boot with that `wsl.conf` applied is where this distribution's
    // `WSLInterop` entry goes (measured on five imports: a trivial session, no
    // script, and the entry was gone three seconds later; every later boot of
    // the same guest leaves it alone). Take that boot here, where it can be
    // checked and repaired, rather than inside the first `vm probe`.
    let _ = Command::new(wsl)
        .current_dir("/mnt/c")
        .args(["-d", distro, "-u", "root", "--", "true"])
        .status();
    std::thread::sleep(std::time::Duration::from_secs(5));
    let interop = restore_interop();
    println!("PASS vm up wsl2-{variant}: {distro} imported, systemd={systemd}, cgroups={cgroups}");
    interop
}

/// Whether this distribution can still start a `.exe`: the `WSLInterop` entry
/// of the kernel-wide `binfmt_misc` table.
fn interop_registered() -> bool {
    Path::new("/proc/sys/fs/binfmt_misc/WSLInterop").is_file()
}

/// Put `WSLInterop` back when another distribution's boot removed it.
///
/// Registration needs root. With a password-less `sudo` it is done here;
/// otherwise the exact line is printed and the caller exits 1, because
/// nothing that follows can reach `wsl.exe`. Returns the exit code.
fn restore_interop() -> u8 {
    const LINE: &str = r#"echo ":WSLInterop:M::MZ::/init:PF" > /proc/sys/fs/binfmt_misc/register"#;
    if interop_registered() {
        return 0;
    }
    let restored = Command::new("sudo")
        .args(["-n", "sh", "-c", LINE])
        .status()
        .is_ok_and(|s| s.success())
        && interop_registered();
    if restored {
        println!("WSLInterop re-registered (the guest's first boot had removed it)");
        return 0;
    }
    eprintln!(
        "FAIL: this distribution lost its WSLInterop binfmt entry at the guest's first boot; re-register it as root and rerun:\n  sudo sh -c '{LINE}'"
    );
    1
}

/// The tier probe plus the WSL2-specific facts the plan asks about — cgroup mode
/// and whether systemd is PID 1 — and, when the object is built, the BPF rows.
fn wsl2_probe_script() -> String {
    let mut s = String::from(TIER_PROBE);
    s.push_str("echo \"cgroup2 mount: $(awk '$3==\"cgroup2\"{print $2; exit}' /proc/mounts)\"; echo \"cgroup v1 controllers: $(grep -c ' cgroup ' /proc/mounts)\"; echo \"pid1: $(cat /proc/1/comm)\"\n");
    // The object itself is staged on NTFS by `wsl2_exec`, which is the only
    // filesystem the target distribution shares with this one.
    if Path::new(PROBE_OBJ).is_file() {
        s.push_str(BPF_PROBE);
    }
    s
}

/// Run a script as root in the distribution and print what it printed.
///
/// The script goes to a file on NTFS and is run from there: an argv-embedded
/// script does not survive `wsl.exe` — Windows argument quoting turns every `"`
/// into `\"` and mangles redirections (measured: awk received literal
/// backslashes and bash saw `2` as a stray token). NTFS is also the only
/// filesystem the target distribution shares with this one; its `/mnt/c` path is
/// the same on both sides.
fn wsl2_exec(
    wsl: &str,
    distro: &str,
    name: &str,
    variant: &str,
    systemd: bool,
    script: &str,
) -> u8 {
    let Some(local) = windows_local_appdata() else {
        eprintln!("FAIL: could not resolve %LOCALAPPDATA% through interop");
        return 1;
    };
    let stage = Path::new(&local).join("aisme").join("vm");
    if std::fs::create_dir_all(&stage).is_err() {
        eprintln!("FAIL: cannot stage under {}", stage.display());
        return 1;
    }
    let mut body = String::from("#!/bin/bash\n");
    if let Some(bpftool) = static_bpftool() {
        if std::fs::copy(&bpftool, stage.join("bpftool")).is_ok() {
            let _ = writeln!(
                body,
                "install -m 755 '{}' /usr/local/bin/bpftool",
                stage.join("bpftool").display()
            );
        }
    }
    if Path::new(PROBE_OBJ).is_file() && std::fs::copy(PROBE_OBJ, stage.join("probe.o")).is_ok() {
        let _ = writeln!(
            body,
            "cp '{}' /root/probe.o",
            stage.join("probe.o").display()
        );
    }
    body.push_str(script);
    let script_path = stage.join(format!("run-{variant}.sh"));
    if std::fs::write(&script_path, body).is_err() {
        eprintln!("FAIL: cannot write {}", script_path.display());
        return 1;
    }
    if systemd {
        hold_open(wsl, distro);
    }
    println!(
        "running in {distro} ({}) …",
        if systemd { "systemd" } else { "no systemd" }
    );
    let out = Command::new(wsl)
        .current_dir("/mnt/c")
        .args(["-d", distro, "-u", "root", "--", "bash"])
        .arg(&script_path)
        .output();
    match out {
        Ok(o) => {
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr)
            );
            for line in text.replace('\0', "").lines() {
                println!("  {}", strip_ansi(line));
            }
            let code = u8::from(!o.status.success());
            println!(
                "{} vm {} wsl2-{variant}",
                if code == 0 { "PASS" } else { "FAIL" },
                name.trim_start_matches("vm ")
            );
            code.max(restore_interop())
        }
        Err(e) => {
            eprintln!("FAIL: wsl.exe did not run: {e}");
            1
        }
    }
}

/// The static `bpftool`, fetched on first use; `None` says so and the guest
/// script falls back to its package manager.
fn static_bpftool() -> Option<PathBuf> {
    let bin = Path::new(BPFTOOL_BIN);
    if bin.is_file() {
        return Some(bin.to_path_buf());
    }
    let _ = std::fs::create_dir_all(DIR);
    let tarball = Path::new(DIR).join("bpftool.tar.gz");
    println!("fetching a static bpftool from {BPFTOOL_URL} …");
    let fetched = Command::new("curl")
        .args(["-fsSL", "-o"])
        .arg(&tarball)
        .arg(BPFTOOL_URL)
        .status()
        .is_ok_and(|s| s.success());
    // The release tarball carries the binary without its execute bit.
    let extracted = fetched
        && Command::new("tar")
            .args(["xzf"])
            .arg(&tarball)
            .args(["-C", DIR, "bpftool"])
            .status()
            .is_ok_and(|s| s.success())
        && Command::new("chmod")
            .arg("755")
            .arg(bin)
            .status()
            .is_ok_and(|s| s.success());
    if !extracted {
        eprintln!(
            "WARN: no static bpftool ({BPFTOOL_URL}); the guest installs its own through apt"
        );
        return None;
    }
    Some(bin.to_path_buf())
}

/// Keep a systemd guest running for the rest of the session.
///
/// `binfmt_misc` is one kernel-wide table shared by every distribution. When a
/// guest in which `systemd-binfmt.service` has run *terminates*, the teardown
/// clears that table, and this distribution loses `WSLInterop`: every `.exe`
/// fails with `exec format error` until a new session is opened in it from
/// Windows. Measured three times here, each loss within a second of the guest
/// stopping, and independently by rancher-desktop#10049 — which also measured
/// that masking the unit does not prevent it. Starting the guest is harmless,
/// so a detached session holds it open and the owner terminates it last.
fn hold_open(wsl: &str, distro: &str) {
    let held = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "setsid '{wsl}' -d '{distro}' -- sleep infinity </dev/null >/dev/null 2>&1 &"
        ))
        .current_dir("/mnt/c")
        .status();
    if held.is_ok_and(|s| s.success()) {
        println!(
            "{distro} is held open: `wsl.exe --terminate {distro}` clears this distribution's interop, so run it last and open a new session here afterwards"
        );
    } else {
        eprintln!("WARN: could not hold {distro} open; when it terminates, this distribution loses interop");
    }
}

/// `%LOCALAPPDATA%` as a Linux path, asked of `cmd.exe` through interop.
fn windows_local_appdata() -> Option<String> {
    let out = Command::new("cmd.exe")
        .args(["/c", "echo %LOCALAPPDATA%"])
        .output()
        .ok()?;
    let win = String::from_utf8_lossy(&out.stdout)
        .trim()
        .replace('\r', "");
    if win.is_empty() || win.contains('%') {
        return None;
    }
    let out = Command::new("wslpath").arg("-u").arg(win).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

fn registered(wsl: &str, distro: &str) -> bool {
    Command::new(wsl)
        .args(["--list", "--quiet"])
        .output()
        .is_ok_and(|o| {
            String::from_utf8_lossy(&o.stdout)
                .replace('\0', "")
                .lines()
                .any(|l| l.trim() == distro)
        })
}

/// A WSL path as Windows sees it, via `wslpath -w`.
fn wslpath(p: &Path) -> Option<String> {
    let abs = std::fs::canonicalize(p).ok()?;
    let out = Command::new("wslpath").arg("-w").arg(abs).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

fn have(tool: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|p| std::env::split_paths(&p).any(|d| d.join(tool).is_file()))
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' && chars.peek() == Some(&'[') {
            for d in chars.by_ref() {
                if d.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Standard base64 with padding; enough for a seed file, no dependency needed.
fn base64(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n =
            chunk.iter().fold(0u32, |acc, &b| (acc << 8) | u32::from(b)) << (8 * (3 - chunk.len()));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(T[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod stage_tests {
    use super::{guarded, install_script, Staged};
    use std::io::Write as _;
    use std::path::PathBuf;
    use std::process::{Command, Stdio};

    fn one(name: &str, sha: &str) -> Staged {
        Staged {
            name: name.to_owned(),
            path: PathBuf::from("/dev/null"),
            sha256: sha.to_owned(),
            size: 42,
        }
    }

    fn sh(script: &str, env: &[(&str, &str)]) -> std::process::Output {
        let mut c = Command::new("sh");
        c.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (k, v) in env {
            c.env(k, v);
        }
        let mut child = c.spawn().expect("this test needs /bin/sh to mean anything");
        child
            .stdin
            .take()
            .expect("piped")
            .write_all(script.as_bytes())
            .expect("write");
        child.wait_with_output().expect("wait")
    }

    /// The prologue is shell, built by string formatting in Rust and staged
    /// through cloud-init YAML before a guest shell sees it. Every layer in that
    /// chain ate an escape at least once while this was written, so the script
    /// goes to a real parser rather than being read by eye.
    #[test]
    fn the_generated_prologue_is_valid_shell() {
        let script = guarded(
            &install_script(&[
                one("aisme-agentd", &"a".repeat(64)),
                one("aisme", &"b".repeat(64)),
            ]),
            "echo ran",
        );
        let mut child = Command::new("sh")
            .arg("-n")
            .stdin(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("this test needs /bin/sh");
        child
            .stdin
            .take()
            .expect("piped")
            .write_all(script.as_bytes())
            .expect("write");
        let out = child.wait_with_output().expect("wait");
        assert!(
            out.status.success(),
            "sh -n rejected the prologue:\n{}\n--- script ---\n{script}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// The regression that a real VM run found: the guard printed "refusing to
    /// run" and then ran the command anyway. A mismatch that looks handled is
    /// worse than no check, so this runs the real script with a hash that
    /// cannot match and asserts the command never executed.
    #[test]
    fn a_hash_mismatch_actually_stops_the_command() {
        let root = std::env::temp_dir().join(format!("aisme-stage-{}", std::process::id()));
        let script = guarded(
            &install_script(&[one("aisme-agentd", &"f".repeat(64))]),
            "echo THE-COMMAND-RAN",
        );
        let out = sh(&script, &[("AISME_ROOT", &root.to_string_lossy())]);
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(stdout.contains("HASH MISMATCH"), "{stdout}");
        assert!(
            !stdout.contains("THE-COMMAND-RAN"),
            "the guard announced a refusal and ran the command anyway:\n{stdout}"
        );
        assert!(stdout.contains("refusing to run"), "{stdout}");
        assert!(!out.status.success(), "a refusal must not exit 0");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// And the other direction: when the hash matches, the command runs. A
    /// guard that refuses everything would pass the test above and be useless.
    #[test]
    fn a_matching_hash_lets_the_command_run() {
        use super::{Digest as _, Sha256};
        let root = std::env::temp_dir().join(format!("aisme-stage-ok-{}", std::process::id()));
        let src = std::env::temp_dir().join(format!("aisme-src-{}", std::process::id()));
        std::fs::create_dir_all(&src).expect("tmp");
        std::fs::write(src.join("aisme-agentd"), b"payload").expect("write");
        // sha256 of "payload", computed here rather than pasted, so the test
        // and the code under test agree by construction.
        let mut h = Sha256::new();
        h.update(b"payload");
        let sha = format!("{:x}", h.finalize());
        // The prologue copies from /opt/aisme; point it at the temp source.
        let script = guarded(
            &install_script(&[one("aisme-agentd", &sha)]),
            "echo THE-COMMAND-RAN",
        )
        .replace("/opt/aisme", &src.to_string_lossy());
        let out = sh(&script, &[("AISME_ROOT", &root.to_string_lossy())]);
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains(&format!("aisme-agentd: ok {}", &sha[..12])),
            "{stdout}"
        );
        assert!(stdout.contains("THE-COMMAND-RAN"), "{stdout}");
        assert!(out.status.success(), "{stdout}");
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&src);
    }

    /// The guest re-hashes what it received; the host's hash has to reach it
    /// intact for that comparison to mean anything.
    #[test]
    fn every_staged_binary_carries_its_full_hash_into_the_guest() {
        let sha = "c".repeat(64);
        let script = install_script(&[one("aisme-agentd", &sha)]);
        assert!(script.contains(&sha), "the full hash must reach the guest");
        assert!(script.contains("sha256sum \"$AISME_ROOT/aisme-agentd\""));
        assert!(
            script.contains("HASH MISMATCH"),
            "a mismatch must be loud, not a silent skip"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{base64, strip_ansi, IMAGES};

    #[test]
    fn base64_matches_the_rfc_vectors() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn ansi_sequences_are_removed_and_text_kept() {
        assert_eq!(strip_ansi("\u{1b}[0;32mPASS\u{1b}[0m ok"), "PASS ok");
    }

    #[test]
    fn every_catalogued_image_names_the_kernel_the_matrix_expects() {
        for i in IMAGES {
            assert!(i.expect.contains('('), "{} has no tier expectation", i.name);
            // The printed expectation and the one `result` compares against
            // are two spellings of one fact, so they are checked to agree:
            // a row whose text says L2- while its list says L1 would print a
            // PASS nobody could interpret.
            assert!(!i.tiers.is_empty(), "{} expects no tier", i.name);
            for tier in i.tiers {
                assert!(
                    i.expect.contains(tier),
                    "{}: `{}` does not name tier {tier}",
                    i.name,
                    i.expect
                );
            }
            assert!(
                i.url.starts_with("https://"),
                "{} is not fetched over https",
                i.name
            );
        }
    }
}
