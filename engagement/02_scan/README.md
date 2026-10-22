# 02_scan — Reconnaissance

**Script:** `recon.sh`  
**Session label:** `scan`  
**ATT&CK:** T1595.001 · T1046 · T1595 · T1595.002  
**Kill-chain phase:** Reconnaissance

---

## Overview

This phase maps the entire testbed: who is alive, what ports are open, what services are running, what OS/firmware the device uses, and whether nmap's vuln scripts surface known weaknesses. The output feeds every later phase — brute-force targets come from open RTSP/SSH/HTTP ports; CVE exploits are gated on confirmed services and firmware versions.

**Target list:** `00_scope/targets.txt` — 41 IPs, professor format (one IP per line, `#` comments).  
**Special host:** `10.100.101.4` (Panda-Pivot) — pre-compromised foothold provided by the professor. Scanned to document its attack surface but skipped in exploit phases.

---

## Pre-session checklist

Run these before anything else:

```bash
# 1. Bring up the WireGuard tunnel
sudo wg-quick up fordaysec

# 2. Confirm tunnel and tools
cd ~/master-thesis
./01_setup/preflight.sh

# 3. Confirm gateway answers (tunnel health check — not a target)
ping -c 3 10.100.101.1

# 4. Confirm at least one IoT device is reachable
ping -c 2 10.100.101.10   # Tapo C200
```

---

## Professor session — one command

Runs the full pipeline in the correct order and wraps it in a dataset episode:

```bash
./02_scan/recon.sh session
```

**Order inside `session`:**
1. Host discovery (ping sweep)
2. masscan — all 65535 TCP ports on all 41 targets, 1000 pps
3. Deep scan (nmap full-port + OS) — CVE targets first, then remaining hosts
4. Vulnerability scan — CVE targets only
5. Surface scan of Panda-Pivot (.4)

**Estimated time:** 3–5 hours (nmap full-port scan is the bottleneck).

---

## Step-by-step (run individually)

### Step 1 — Host discovery

Finds which devices are actually online right now.

```bash
./02_scan/recon.sh discovery
```

- Uses `nmap -sn` (ping sweep) — no port scanning, no impact on devices.
- Excludes gateway `10.100.101.1` (infra, not a target).
- Evidence: `runs/scan/<ts>_discovery/discovery.{nmap,gnmap,xml}`

**Expected:** 30–40 of the 41 devices respond (some IoT devices sleep or block ICMP).  
**Cross-check:** compare live hosts against `00_scope/targets.txt` — note any device that's down before its deeper scan.

---

### Step 2 — masscan (fast TCP port sweep)

Finds open ports across all 41 targets in ~2 minutes.

```bash
./02_scan/recon.sh masscan
```

- Rate: 1000 pps on `fordaysec` interface — safe for IoT (do NOT increase).
- `--wait 10` gives straggler devices 10 s to respond after the sweep.
- Output: list format (`-oL`) in `runs/scan/<ts>_masscan/masscan.txt`.

**What to look for immediately:**
- Port `37777` on `.12` → Amcrest DHIP (CVE-2020-5735 / CVE-2020-5736)
- Port `554` on `.10` / `.19` / `.20` → RTSP cameras (CVE-2026-1871, brute RTSP)
- Port `5555` on `.57` → ADB on Fire TV — **strong lateral pivot if open**
- Port `9999/udp` on L530s (`.34 .41-.45`) → Tapo local API (CVE-2023-38907)
- Port `80` on Shellys (`.39 .40`) → HTTP RPC (CVE-2026-64823)

---

### Step 3 — Port scan + service/version

Full TCP range and top-50 UDP on each host, with service/version detection.

```bash
# One host:
./02_scan/recon.sh ports 10.100.101.10

# Multiple hosts:
./02_scan/recon.sh ports 10.100.101.10 10.100.101.12 10.100.101.56

# All inventory:
./02_scan/recon.sh all-inventory
```

Per host evidence:
- `tcp.nmap` / `tcp.gnmap` / `tcp.xml` — full TCP scan
- `udp.nmap` / `udp.gnmap` / `udp.xml` — top-50 UDP

---

### Step 4 — OS + firmware fingerprint

```bash
./02_scan/recon.sh fingerprint 10.100.101.10
./02_scan/recon.sh fingerprint 10.100.101.12
```

- `nmap -O --osscan-guess -sV` — combines OS detection with service version.
- IoT devices often return generic Linux fingerprints; the firmware version comes from service banners (HTTP headers, RTSP Server field, ONVIF `GetDeviceInformation`).

---

### Step 5 — Vulnerability scan

```bash
# CVE-priority targets:
./02_scan/recon.sh vuln 10.100.101.10   # Tapo C200
./02_scan/recon.sh vuln 10.100.101.12   # Amcrest IP2M
./02_scan/recon.sh vuln 10.100.101.56   # Reolink D340W
./02_scan/recon.sh vuln 10.100.101.39   # Shelly Plug S
./02_scan/recon.sh vuln 10.100.101.40   # Shelly2PM Gen4
```

Scripts run: `vuln`, `http-enum`, `http-headers`, `http-methods`, `http-title`.  
Output: `runs/scan/<ts>_<ip>/vuln.{nmap,gnmap,xml}`

---

### All scans on one host

```bash
./02_scan/recon.sh all 10.100.101.10
```

Runs: ports → fingerprint → vuln in sequence.

---

## Device scan priority and expected findings

| Priority | IP | Device | Key ports | CVE / Next phase |
|----------|----|--------|-----------|-----------------|
| **1** | `.10` | Tapo C200 | 554 (RTSP), 443 (HTTPS) | CVE-2026-1871 DoS, CVE-2021-4045 RCE, CVE-2025-14300 probe |
| **1** | `.12` | Amcrest IP2M-841B-V3 | **37777** (DHIP), 80, 2020 (ONVIF) | CVE-2020-5735 overflow, CVE-2020-5736 NPD |
| **1** | `.34 .41–.45` | Tapo L530 ×6 | 9999/udp (Tapo LAN) | CVE-2023-38907 replay |
| **1** | `.55` | Meross MSG100 | 80 (HTTP), MQTT | CVE-2021-35067 garage replay |
| **1** | `.56` | Reolink D340W | 80, 443, 9000 | CVE-2025-55637 DDNS injection |
| **1** | `.39` `.40` | Shelly Plug S / 2PM | 80 (HTTP RPC) | CVE-2026-64823 HA XSS |
| **2** | `.57` | Fire TV 4K | **5555 (ADB!)**, 8008, 8009 | Lateral pivot if ADB open |
| **2** | `.11 .21 .23` | ESP sensors | 80, 6053 (ESPHome) | Web fingerprint, OTA |
| **2** | `.19` | TC70 camera | 554, 80 | RTSP brute |
| **2** | `.20` | Reolink E1 | 80, 9000 | Web, ONVIF |
| **2** | `.28` | Echo Dot Gen 4 | 4070, 8080, 55442 | MITM, lateral |
| **3** | `.47 .48` | HBN Plug | 80 | Web |
| **3** | `.49` | Beok TOL47 Thermostat | 80 | Web |
| **3** | `.50` | SwitchBot Water Leak | varies | MITM observation |
| **3** | `.51` | Sonoff DW2 | 80, 8081 | Web |
| **3** | `.52–.54` | H5179 Humidity | varies | MITM observation |
| **special** | `.4` | **Panda-Pivot** | all | Pre-compromised foothold — scan surface only, use in lateral phase |

---

## Panda-Pivot (10.100.101.4)

The professor provided this host as a pre-compromised foothold for the lateral movement phase. It is **not a target** for exploitation — it is the **starting point** for phase 10 (lateral).

```bash
# Scan its exposed surface (already included in session):
sudo nmap -sS -sV -O -T3 10.100.101.4 -oA ~/master-thesis/runs/scan/pivot_surface
```

Document what services are running on it — this determines what lateral movement tools are available (SSH? HTTP? Meterpreter?).

---

## Recording findings

After each scan, append one line to the **Findings** section at the bottom of this file:

```
<ip>  <device>  | open: <ports>  | interesting: <notes>  | feeds: <next CVE/phase>
```

Then label the run folder:

```bash
echo "success" > ~/master-thesis/runs/scan/<folder>/result
```

---

## Evidence structure

```
runs/scan/
├── <ts>_discovery/
│   ├── cmd.txt          ← exact command (for thesis citation)
│   ├── stdout.txt       ← raw output
│   ├── discovery.nmap
│   ├── discovery.gnmap
│   └── discovery.xml
├── <ts>_masscan/
│   ├── cmd.txt
│   ├── masscan.txt      ← open port list
│   └── stdout.txt
└── <ts>_10.100.101.10/
    ├── cmd.txt
    ├── stdout.txt
    ├── tcp.{nmap,gnmap,xml}
    ├── udp.{nmap,gnmap,xml}
    ├── osfp.{nmap,gnmap,xml}
    ├── vuln.{nmap,gnmap,xml}
    └── result           ← add manually: success / partial / fail
```

---

## After the session — assemble dataset

```bash
./dataset/assemble.sh
sudo wg-quick down fordaysec
```

---

## Findings

_(fill in as you go — one line per host)_
