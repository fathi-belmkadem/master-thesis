# Master Thesis — IoT Security Testbed Attack Simulation & Autonomous Agent Dataset

**Author:** Fathi Belmkadem  
**University:** University of Passau  
**Programme:** Master of Science in Artificial Intelligence  
**Supervisor:** [Professor name]  
**Date:** October 2026

---

## Project Overview

This repository contains the complete, reproducible implementation of the thesis's
two interlinked objectives:

### Objective 1 — Attack Simulation (engagement/)

Reproduce a structured set of real-world IoT attack scenarios against an **institutionally
approved, isolated lab testbed** (40 devices, WireGuard VPN access only). Every attack
is documented with exact commands, raw tool output, timestamps, and ATT&CK IDs so each
scenario can be cited directly in the thesis and reproduced by any examiner with access
to the lab.

**9 CVEs** across 7 device types are implemented, ranging from unauthenticated buffer
overflows and session-replay flaws to command injection and XSS in management software.

### Objective 2 — Autonomous Agent Dataset (engagement/dataset/)

The attack runs double as **labeled training data** for an autonomous attack-selection
agent. Each run produces a `(state_before → action → outcome → state_after)` step that
is assembled into an imitation-learning trajectory. The agent learns to select the next
attack given the current knowledge state, following the kill-chain.

---

## Repository Structure

```
Master thesis/
│
├── README.md                      ← this file (project overview for the professor)
├── .gitignore                     ← excludes keys, configs, evidence, pcaps
│
└── engagement/                    ← all operational scripts and documentation
    ├── README.md                  ← engagement workspace guide (start here)
    ├── lib.sh                     ← shared scope guard + markers + episode helpers
    ├── capture.sh                 ← optional tunnel pcap
    │
    ├── 00_scope/                  ← authorization, device inventory, methodology
    ├── 01_setup/                  ← Kali setup guide + preflight check script
    ├── 02_scan/                   ← reconnaissance (nmap)
    ├── 03_web/                    ← web attack surface (nikto, sqlmap, whatweb)
    ├── 04_brute_force/            ← credential attacks (hydra)
    ├── 05_cve_exploit/            ← 9 CVEs: exploit scripts + research matrix
    ├── 06_c2/                     ← command & control (Sliver)
    ├── 07_dos_ddos/               ← denial of service (hping3, slowhttptest)
    ├── 08_exfil/                  ← exfiltration (SCP, iodine DNS tunnel)
    ├── 09_mitm/                   ← man-in-the-middle (bettercap)
    ├── 10_lateral/                ← lateral movement (Metasploit, proxychains)
    ├── wordlists/                 ← seed credential lists
    └── dataset/                   ← agent training dataset pipeline
```

> `engagement/runs/` (generated evidence) is gitignored and lives only on the attack host.

---

## Testbed Summary

| Item | Detail |
|------|--------|
| Lab devices | 40 IoT devices (cameras, bulbs, plugs, sensors, voice assistant, garage opener) |
| Access method | WireGuard VPN tunnel — attack host at `10.100.101.60`, devices at `10.100.101.X` |
| Authorization | Institutionally approved, isolated testbed — author's own devices |
| Third-party targeting | **None** |
| Self-propagating malware | **None** |

---

## CVE Coverage (9 CVEs)

| CVE | Device | Type | Script |
|-----|--------|------|--------|
| CVE-2026-1871 | Tapo C200 | RTSP Authorization header overflow → DoS | `exploit.sh c200` |
| CVE-2021-4045 | Tapo C200 | uhttpd unauthenticated RCE | `exploit.sh c200-uhttpd` |
| CVE-2025-14300 | Tapo C200 | Unauthenticated connectAP interface | `exploit.sh c200-connectap` |
| CVE-2020-5735 | Amcrest IP2M-841B-V3 | Authenticated DHIP stack overflow → DoS/RCE | `exploit.sh amcrest` |
| CVE-2020-5736 | Amcrest IP2M-841B-V3 | Authenticated DHIP null-pointer dereference → DoS | `exploit.sh amcrest-npd` |
| CVE-2023-38907 | Tapo L530 (×6) | Session-nonce replay → unauthorized control | `exploit.sh l530` |
| CVE-2021-35067 | Meross MSG100 | HTTP session replay → garage door actuation | `exploit.sh meross` |
| CVE-2025-55637 | Reolink D340W | DDNS command injection | `exploit.sh reolink-ddns` |
| CVE-2026-64823 | Shelly → Home Assistant | XSS via Shelly thumb URI | `ha_xss.sh poc` |

---

## Agent Formulation (Dataset Objective)

The training dataset represents the attacker's decision problem as a Markov Decision Process:

- **State**: the attacker's current knowledge about each device (alive?, open ports, services,
  firmware version, discovered vulns, recovered credentials, foothold established, phase reached)
- **Action**: one of the catalogue techniques (scan, web, brute_force, cve_exploit, c2, dos,
  exfil, mitm, lateral) with its parameters
- **Reward**: shaped on kill-chain progress (advancing to a later phase = positive reward;
  crashing a device needed for later phases = negative reward)
- **Learning**: imitation learning (behaviour cloning) from expert demonstration trajectories,
  with optional RL fine-tuning in the isolated lab

See `engagement/dataset/DATASET.md` for the full formulation, state schema, and action space.

---

## How to Use This Repository

1. **Read the authorization and scope documents first**: `engagement/00_scope/scope.md`
2. **Set up the Kali attack host**: follow `engagement/01_setup/attack-host-setup.md`
3. **Run the preflight check**: `./engagement/01_setup/preflight.sh`
4. **Follow the engagement README**: `engagement/README.md` has the complete step-by-step guide
5. **After each session, assemble the dataset**: `./engagement/dataset/assemble.sh`

---

## Security and Privacy

- All evidence (`runs/`), WireGuard keys (`*.key`, `*.conf`), and pcap files are **gitignored**
  and never leave the attack host.
- Recovered credentials are stored only in `runs/` (gitignored).
- This repository contains **no exploit payloads** — only the scripts that orchestrate
  standard Kali tools and the PoC helpers that are created at runtime inside `runs/`.
