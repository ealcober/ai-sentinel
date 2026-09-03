# Security policy

## Reporting a vulnerability

Report privately through GitHub's [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability) on this repository. Do not open a public issue.

Please include what you did, what happened, and what you expected. A proof of concept helps and is not required.

**Acknowledgement within 7 days. A first assessment within 30 days.** This project is maintained by one person; those are honest figures rather than an SLA.

## Scope

The threat model is in [`docs/security/01_threat-model.md`](docs/security/01_threat-model.md), and reading its §2 before reporting will save us both time. In particular, two adversaries are **explicitly out of scope for prevention**, by design and with the reasoning written down:

- **A human attacker who already has root on the machine.** They can stop the daemon and rewrite the local log. What survives them is external root anchoring, not local prevention.
- **An implant engineered to detect and evade eBPF.** Contesting it would require techniques — rewriting another process's memory to hide — that this project refuses on purpose (`H-05`, `I-02`).

A report that AISME can be disabled by root, or evaded by a purpose-built anti-eBPF implant, is a documented non-goal rather than a vulnerability. A report that AISME **fails to record** that either happened is a real finding, because tamper-evidence is the property that is claimed (`I-18`).

## What is in scope, and valued

- Any way to make AISME **modify an observed process** (`I-01`) or hide itself (`I-02`).
- Any way to make a suppression rule **remove a record or weaken enforcement** (`I-26`).
- Any way to get the Observer LLM to **lower** a severity or authorize anything (`I-04`).
- Any way for a remote device to authorize without a hardware signature (`I-06`), or for the relay to observe plaintext (`I-07`).
- Any way for the monitored agent to change policy, grants or suppressions (`F7.PS.08`).
- A denial of service against the host caused by AISME (`I-10`).
