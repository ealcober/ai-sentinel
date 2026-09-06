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
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

/// A catalogued image. Only `ubuntu-24.04` is measured so far; the rest boot the
/// same way or fail visibly at boot — this command reports what happens.
struct Image {
    name: &'static str,
    url: &'static str,
    /// The kernel the plan's matrix expects from it (§F0.VM.02).
    expect: &'static str,
}

const IMAGES: &[Image] = &[
    Image { name: "ubuntu-20.04", url: "https://cloud-images.ubuntu.com/focal/current/focal-server-cloudimg-amd64.img", expect: "5.4 (L1)" },
    Image { name: "debian-11", url: "https://cloud.debian.org/images/cloud/bullseye/latest/debian-11-genericcloud-amd64.qcow2", expect: "5.10 (L2-)" },
    Image { name: "ubuntu-22.04", url: "https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img", expect: "5.15 (L2)" },
    Image { name: "debian-12", url: "https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.qcow2", expect: "6.1 (L2)" },
    Image { name: "ubuntu-24.04", url: "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img", expect: "6.8 (L2/L3)" },
    Image { name: "fedora-40", url: "https://archives.fedoraproject.org/pub/archive/fedora/linux/releases/40/Cloud/x86_64/images/Fedora-Cloud-Base-Generic.x86_64-40-1.14.qcow2", expect: "6.8 (L3)" },
    Image { name: "ubuntu-26.04", url: "https://cloud-images.ubuntu.com/resolute/current/resolute-server-cloudimg-amd64.img", expect: "7.0 (L2/L3, Landlock audit)" },
];

const DIR: &str = "vm/images";

/// The verification probe object, built by `build-ebpf` alongside the product crate.
const PROBE_OBJ: &str = "tests/probes/ebpf/target/bpfel-unknown-none/release/aisme-ebpf-verify";

pub(crate) fn run(name: &str, args: &[&str]) -> u8 {
    for tool in ["qemu-system-x86_64", "qemu-img", "genisoimage"] {
        if !have(tool) {
            eprintln!("skip: {tool} is not installed; `cargo xtask doctor` names the package.");
            return SKIP;
        }
    }
    let Some((&image_name, rest)) = args.split_first() else {
        eprintln!("usage: cargo xtask {name} <image> [-- command]");
        eprintln!(
            "images: {}",
            IMAGES.iter().map(|i| i.name).collect::<Vec<_>>().join(", ")
        );
        return 1;
    };
    let Some(image) = IMAGES.iter().find(|i| i.name == image_name) else {
        eprintln!("error: unknown image `{image_name}`; see `cargo xtask vm up` for the list.");
        return 1;
    };
    match name {
        "vm up" => up(image),
        "vm run" => {
            let cmd = rest
                .iter()
                .skip_while(|a| **a == "--")
                .copied()
                .collect::<Vec<_>>()
                .join(" ");
            if cmd.is_empty() {
                eprintln!("usage: cargo xtask vm run <image> -- <command>");
                return 1;
            }
            boot(
                image,
                &format!("echo \"=====AISME-BEGIN=====\"\n{cmd}\necho \"=====AISME-END=====\""),
                "run",
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

/// The capability probe plus, when the object exists, the two BPF rows. Output is
/// the guest's own, between markers, so nothing here is inferred.
fn probe(image: &Image) -> u8 {
    let mut script = String::from(TIER_PROBE);
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
    let seed = match write_seed(image, script) {
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

fn write_seed(image: &Image, script: &str) -> Result<PathBuf, String> {
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
echo "lsm: $(cat /sys/kernel/security/lsm 2>/dev/null || echo unreadable)"
python3 - <<'PY'
import ctypes, gzip, os
libc = ctypes.CDLL(None, use_errno=True); libc.syscall.restype = ctypes.c_long
abi = libc.syscall(ctypes.c_long(444), None, ctypes.c_size_t(0), ctypes.c_uint32(1))
cfg = gzip.open("/proc/config.gz", "rt").read() if os.path.exists("/proc/config.gz") else open("/boot/config-" + os.uname().release).read()
k = lambda key: next((l for l in cfg.splitlines() if l.startswith(key + "=")), key + " not set")
lsm = open("/sys/kernel/security/lsm").read().strip() if os.path.exists("/sys/kernel/security/lsm") else ""
btf = os.path.exists("/sys/kernel/btf/vmlinux"); cg2 = " cgroup2 " in open("/proc/mounts").read()
print("landlock_abi:", abi if abi > 0 else "unavailable")
for key in ("CONFIG_BPF_LSM", "CONFIG_CGROUP_BPF", "CONFIG_DEBUG_INFO_BTF", "CONFIG_LSM"): print(k(key))
print("btf_vmlinux:", "present" if btf else "absent"); print("cgroup2:", "yes" if cg2 else "no")
tier = "L3" if "bpf" in lsm.split(",") else "L2" if (abi > 0 and "landlock" in lsm and cg2) else "L2-" if btf else "L1"
print("tier:", tier)
PY
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
            assert!(
                i.url.starts_with("https://"),
                "{} is not fetched over https",
                i.name
            );
        }
    }
}
