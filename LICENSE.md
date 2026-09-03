# Licensing

AISME is open source. The map below is deliberate, and one line of it is not a choice.

| Path | Licence | SPDX |
|---|---|---|
| `crates/aisme-ebpf/**` — the eBPF programs | **GPL-2.0-only** | `GPL-2.0-only` |
| `crates/aisme-ebpf-common/**` — wire types shared with the kernel side | **GPL-2.0-only OR BSD-2-Clause** | `GPL-2.0-only OR BSD-2-Clause` |
| Everything else in `crates/`, `sdk/`, `mobile/`, `ui/`, `xtask/`, `driver/`, `tests/` | **Apache-2.0** | `Apache-2.0` |
| `docs/**`, including `docs/research/` | **CC-BY-4.0** | `CC-BY-4.0` |

Full texts: [`LICENSE-APACHE`](LICENSE-APACHE), [`LICENSE-GPL`](LICENSE-GPL), [`LICENSE-BSD`](LICENSE-BSD). Attribution: [`NOTICE`](NOTICE).

## Why the eBPF programs are GPL

This is not a preference. Loading a BPF program follows the same licence rules as loading a kernel module: the verifier inspects which helpers the program calls, and a helper marked `gpl_only` — `bpf_probe_read` among them, and roughly a quarter of the helper set — requires the program to declare a GPL-compatible licence. AISME's probes use several. So `crates/aisme-ebpf` is GPL-2.0-only, and it would be GPL-2.0-only under any project's licensing policy.

The boundary stops there. The Linux kernel documentation is explicit that a user-space program interacting with eBPF through the syscall interface is not a derivative work of the BPF program, in the same way it is not a derivative work of any other kernel interface. AISME's user-space engine is therefore free to be Apache-2.0, and it is.

`crates/aisme-ebpf-common` sits on the boundary: the same `#[repr(C)]` structs are compiled into the GPL kernel side and linked into the Apache user-space side. Dual-licensing it `GPL-2.0-only OR BSD-2-Clause` lets each side take the licence it needs. This is the arrangement `libbpf` uses for the same reason.

## Why Apache-2.0 for everything else

Two properties this project needs and MIT does not have:

**An express patent grant** (§3). AISME implements techniques that are not obvious — the permission and suppression model, the detector catalogue, the tiered enforcement design. Apache-2.0 grants users a patent licence from every contributor and terminates it for anyone who initiates patent litigation over the work. That protection runs in both directions and it is the reason to prefer Apache-2.0 over MIT here.

**A `NOTICE` file** (§4d). Attribution that survives into derivative works, as a licence obligation rather than a courtesy.

## Why not a copyleft licence for the engine

AGPL protects against a specific threat: someone runs your software as a hosted service and returns nothing. AISME is a workstation agent and an on-device mobile engine. Its only server component, the relay, is designed to be blind and self-hostable — it forwards ciphertext and holds no plaintext. The door AGPL closes is barely open here.

Against that, copyleft carries a real cost for this project, and it is sharpest at the SDK. The **AI Sentinel SDK** exists to be embedded in third-party AI applications; the plan treats that as the strategic component, the thing that turns AISME into an instrumentation standard rather than a permanent reverse-engineering effort. A copyleft SDK cannot be embedded in a proprietary application, so a copyleft SDK would not be adopted, and the strategy would not work. The SDK must be permissive for the same reason it exists.

## Trademarks

Apache-2.0 §6 does not grant trademark rights, deliberately. The names **AISME**, **AI Sentinel** and **AI Sentinel SDK**, and any associated logos, are not licensed by this repository's licences. You may fork the code; please do not use the names for your fork in a way that suggests it is this project.

## Contributing

By contributing you certify the [Developer Certificate of Origin](https://developercertificate.org/) with a `Signed-off-by` line. See [`CONTRIBUTING.md`](CONTRIBUTING.md). Contributors keep their copyright: there is no CLA and no copyright assignment, which also means **this project cannot be relicensed without every contributor's agreement.** That is intentional.

## Citing this work

The design work — the implementation plan, the two review reports and the threat model — is citable. See [`CITATION.cff`](CITATION.cff).
