# IoT Testbed Attack Simulation — Engagement Workspace

**Author:** Fathi Belmkadem — Master's thesis, University of Passau  
**Supervisor-approved, institutionally isolated testbed. All devices are the author's own.**

---

## Purpose

This workspace is the operational core of the thesis's first objective: **reproduce a structured
set of real-world IoT attack scenarios against an approved, isolated lab network**, collect
reproducible evidence, and assemble that evidence into a labeled training dataset for an
**autonomous attack-selection agent** (the thesis's second objective).

Every script in this workspace:
- Validates the target IP against the WireGuard scope (`10.100.101.0/24`) before touching anything
- Writes `START` / `STOP` markers to `runs/markers.log` so every action is time-stamped and attributable
- Saves the exact command and raw output into `runs/<phase>/<timestamp>_<target>/` so results are reproducible
- Never touches the gateway (`10.100.101.1`) or any address outside the tunnel subnet

---

## Lab Architecture

```
Internet
    │
    └── WireGuard endpoint  195.37.127.2:15201
            │
            │  Encrypted tunnel (MTU 1420)
            │
     ┌──────┴──────────────────────────────────────────┐
     │  Attack host (Kali Linux)                         │
     │  WireGuard address: 10.100.101.60/32              │
     │  Interface: fordaysec                             │
     └──────┬──────────────────────────────────────────┘
            │
     10.100.101.0/24  ←── all 40 lab devices reachable here
            │
     ┌──────┴─────────────────────────────────────────┐
     │  Isolated Lab Network (10.21.30.0/24)           │
     │  40 IoT devices: cameras, bulbs, plugs,         │
     │  sensors, voice assistant, garage opener, etc.  │
     │  Home Assistant for monitoring / markers        │
     └────────────────────────────────────────────────┘
```

**Every device has two IPs**: its lab-side `10.21.30.X` address and its WireGuard tunnel `10.100.101.X` address.
**Always use the `10.100.101.X` (WireGuard) address** from the attack host.

---

## Workspace Layout

```
engagement/
│
├── README.md                    ← you are here
├── lib.sh                       ← shared helpers (scope guard, markers, episode brackets)
├── capture.sh                   ← optional tunnel pcap, bracketed to an episode
│
├── 00_scope/                    ← rules of engagement, device inventory, methodology
│   ├── README.md
│   ├── scope.md                 ← authorization, network ranges, safety rules
│   ├── targets.csv              ← 40 devices: model, IPs, MAC, firmware, class
│   └── methodology.md           ← kill-chain phases, ATT&CK IDs, evidence convention
│
├── 01_setup/                    ← one-time attack host setup
│   ├── README.md
│   ├── attack-host-setup.md     ← Kali: WireGuard, tool install, verification
│   └── preflight.sh             ← verify WireGuard + toolchain before every session
│
├── 02_scan/                     ← Phase 1: Reconnaissance
│   ├── README.md
│   └── recon.sh                 ← nmap discovery / ports / fingerprint / vuln scan
│
├── 03_web/                      ← Phase 2: Web attack surface
│   ├── README.md
│   └── web.sh                   ← whatweb, nikto, sqlmap
│
├── 04_brute_force/              ← Phase 3: Credential attacks
│   ├── README.md
│   └── brute.sh                 ← hydra (SSH/Telnet/RTSP/HTTP)
│
├── 05_cve_exploit/              ← Phase 4: CVE exploitation (9 CVEs across 7 devices)
│   ├── README.md
│   ├── exploit.sh               ← 8 sub-commands, one per CVE / device
│   ├── ha_xss.sh                ← CVE-2026-64823: Home Assistant Shelly XSS
│   ├── README_RESEARCH_MATRIX.md← research status, sources, open issues
│   ├── research_matrix.csv      ← machine-readable version of the matrix
│   └── research/                ← one .md file per CVE (source refs, affected versions)
│
├── 06_c2/                       ← Phase 5: Command & Control
│   ├── README.md
│   └── c2.sh                    ← Sliver C2 beacon: gen / serve / deploy / list
│
├── 07_dos_ddos/                 ← Phase 6: Denial of Service
│   ├── README.md
│   └── dos.sh                   ← hping3 (SYN/UDP/ICMP), slowhttptest (HTTP)
│
├── 08_exfil/                    ← Phase 7: Data Exfiltration
│   ├── README.md
│   └── exfil.sh                 ← SCP, curl, iodine DNS tunnel
│
├── 09_mitm/                     ← Phase 8: Man-in-the-Middle
│   ├── README.md
│   └── mitm.sh                  ← bettercap ARP poison, DNS spoof, tcpdump
│
├── 10_lateral/                  ← Phase 9: Lateral Movement
│   ├── README.md
│   └── lateral.sh               ← Metasploit pivot / proxychains nmap / SSH hop
│
├── wordlists/                   ← seed credential lists for brute_force phase
│   ├── README.md
│   ├── users.txt
│   └── passwords.txt
│
├── dataset/                     ← agent training dataset pipeline
│   ├── DATASET.md               ← formulation, state/action space, reward design
│   ├── actions.json             ← machine-readable action space (all CVEs + techniques)
│   ├── state_schema.json        ← per-target observation model
│   ├── assemble.py              ← trajectory assembler: runs/ → trajectories.jsonl
│   ├── assemble.sh              ← wrapper: python3 -I assemble.py
│   └── cve_inventory.csv        ← CVE inventory cross-referenced with device firmware
│
└── runs/                        ← GENERATED — never committed (see .gitignore)
    ├── markers.log              ← START/STOP entries for every action
    ├── CURRENT_EPISODE          ← active episode id (if any)
    ├── scan/                    ← one folder per run, per phase
    ├── web/
    ├── brute_force/
    ├── cve_exploit/
    ├── c2/
    ├── dos/
    ├── exfil/
    ├── mitm/
    ├── lateral/
    └── pcap/                    ← capture.sh pcaps (gitignored)
```

---

## Attack Kill-Chain and Phase Order

The attacks follow the Lockheed Martin Cyber Kill Chain mapped to MITRE ATT&CK:

| Step | Folder | Phase | What it does | Run order |
|------|--------|-------|--------------|-----------|
| 0 | `01_setup` | — | Verify WireGuard + toolchain | Once, before everything |
| 1 | `02_scan` | Reconnaissance | Discover devices, open ports, OS/firmware, vulns | **First** |
| 2 | `03_web` | Delivery → Exploitation | Fingerprint web UIs, scan for misconfigs, SQLi/XSS | After scan |
| 3 | `04_brute_force` | Exploitation | Credential attacks on SSH/RTSP/HTTP | After web |
| 4 | `05_cve_exploit` | Exploitation | Trigger specific CVEs (see table below) | After brute |
| 5 | `09_mitm` | Delivery | ARP poison (required before replay CVEs) | Before replay CVEs |
| 6 | `06_c2` | Command & Control | Deploy Sliver beacon to compromised host | After foothold |
| 7 | `08_exfil` | Actions on Objectives | Pull files over SSH/curl/DNS tunnel | After foothold |
| 8 | `10_lateral` | Lateral Movement | Pivot through a compromised device | After C2 |
| 9 | `07_dos_ddos` | Actions on Objectives | SYN/UDP/ICMP/HTTP floods | **Last per device** |

> **Rule**: always run disruptive actions (DoS, crash-inducing CVEs) **last** for each device,
> one device at a time. Verify recovery with `./01_setup/preflight.sh` before continuing.

---

## CVE Coverage

9 CVEs across 7 devices in the professor's inventory:

| CVE | Device | Script | Risk | Status |
|-----|--------|--------|------|--------|
| CVE-2026-1871 | Tapo C200 `.10` | `exploit.sh c200` | HIGH — DoS | Partially verified |
| CVE-2021-4045 | Tapo C200 `.10` | `exploit.sh c200-uhttpd` | CRITICAL — RCE | Version-gated |
| CVE-2025-14300 | Tapo C200 `.10` | `exploit.sh c200-connectap` | HIGH — unauthenticated API | Partially verified |
| CVE-2020-5735 | Amcrest IP2M-841B `.12` | `exploit.sh amcrest` | HIGH — auth DoS/RCE | Partially verified |
| CVE-2020-5736 | Amcrest IP2M-841B `.12` | `exploit.sh amcrest-npd` | HIGH — auth DoS | Partially verified |
| CVE-2023-38907 | Tapo L530 `.34/.41-.45` | `exploit.sh l530` | MEDIUM-HIGH — replay | **Confirmed affected** |
| CVE-2021-35067 | Meross MSG100 `.55` | `exploit.sh meross` | HIGH — replay | Version-gated |
| CVE-2025-55637 | Reolink D340W `.56` | `exploit.sh reolink-ddns` | CRITICAL — cmd injection | Unverified — probe only |
| CVE-2026-64823 | Shelly `.39/.40` via HA | `ha_xss.sh poc` | MEDIUM-HIGH — XSS | Partially verified |

See `05_cve_exploit/README.md` for full details on each CVE, affected versions,
and what the script actually does.

---

## Getting Started (Step by Step)

### Step 1 — One-time setup on Kali

```bash
# Follow 01_setup/attack-host-setup.md to install WireGuard + tools
# Then verify:
./01_setup/preflight.sh
```

### Step 2 — Make scripts executable

```bash
chmod +x engagement/{02_scan,03_web,04_brute_force,05_cve_exploit,06_c2,07_dos_ddos,08_exfil,09_mitm,10_lateral}/*.sh
chmod +x engagement/lib.sh engagement/capture.sh
```

### Step 3 — Reconnaissance

```bash
./02_scan/recon.sh discovery                  # who is alive?
./02_scan/recon.sh ports 10.100.101.10        # full port scan, one device
./02_scan/recon.sh all-inventory              # all 40 devices (long-running, run overnight)
```

### Step 4 — Web and brute force

```bash
./03_web/web.sh survey 10.100.101.12          # whatweb + nikto on Amcrest
./04_brute_force/brute.sh rtsp 10.100.101.10  # RTSP creds on Tapo C200
```

### Step 5 — CVE exploitation

```bash
# Replay CVEs need MITM first:
./09_mitm/mitm.sh arp 10.100.101.41           # position on L530 link
./05_cve_exploit/exploit.sh l530 10.100.101.41 # replay session nonce

# Detection probes (safe):
./05_cve_exploit/exploit.sh c200-connectap 10.100.101.10
./05_cve_exploit/exploit.sh reolink-ddns   10.100.101.56

# DoS CVEs — LAST:
./05_cve_exploit/exploit.sh c200    10.100.101.10
./05_cve_exploit/exploit.sh amcrest 10.100.101.12 -u admin -p <recovered_pass>
./01_setup/preflight.sh   # verify recovery after each
```

---

## Building the Training Dataset

The end goal is an **autonomous attack-selection agent** trained on labeled trajectories.
See `dataset/DATASET.md` for the full formulation. Data collection wraps around normal runs:

```bash
. ./lib.sh
episode_start tapo_c200_campaign
./capture.sh start tapo_c200_campaign          # optional tunnel pcap

# ... run scan → web → brute → cve actions ...

./capture.sh stop  tapo_c200_campaign
episode_stop  tapo_c200_campaign

# Label each run:
echo success > runs/cve_exploit/<ts>_10.100.101.10/result

# Assemble trajectories:
./dataset/assemble.sh   # → dataset/out/{trajectories.jsonl, manifest.csv, episodes.json}
```

---

## Evidence Structure

Every run creates a self-contained folder under `runs/<phase>/<timestamp>_<target>/`:

| File | Content |
|------|---------|
| `cmd.txt` | Exact command — use this to reproduce the run |
| `stdout.txt` | Raw tool output |
| `result` | Outcome label: `success` / `fail` / `partial` / `wedged` (add manually) |
| `notes.md` | Optional: what was observed, ATT&CK IDs, follow-up actions |
| `*.pcap` | If capture.sh was running |
| `*_poc.py` | PoC source for CVE runs — citable in the thesis |

`runs/` is gitignored. Evidence that may contain recovered credentials or sensitive
device information never leaves your attack host.

---

## Scope Summary

| Allowed | Not allowed |
|---------|-------------|
| `10.100.101.2–.254` (lab devices) | `10.100.101.1` (gateway — infra only) |
| All 40 devices in `targets.csv` | Any IP outside `10.100.101.0/24` |
| PoC tools that crash ONE device | Tools targeting multiple devices simultaneously |
| Recovering credentials within the lab | Storing credentials in git / shared locations |
| Disruptive actions (DoS/CVE-DoS) with recovery documented | Disruptive actions without a recovery plan |
