# Recon Session — Quick Reference

**Goal:** Run the full reconnaissance pipeline across all 40 testbed devices.  
**Time estimate:** 2–4 hours (masscan is fast; nmap full-port is slow per host).

---

## Setup (run once at start of session)

```bash
# 1. Bring up the WireGuard tunnel
sudo wg-quick up fordaysec

# 2. Verify tunnel + tools
cd ~/master-thesis
./01_setup/preflight.sh

# 3. Confirm gateway is reachable (tunnel check — not a target)
ping -c 3 10.100.101.1
```

---

## Option A — Full automated session (one command)

Runs everything in order: discovery → masscan → per-host port+OS scan → vuln scan on CVE targets.

```bash
./02_scan/recon.sh session
```

---

## Option B — Step by step

### Step 1 — Host discovery (who is alive?)
```bash
./02_scan/recon.sh discovery
```
Expected: ~30–40 of the 40 devices respond (some IoT devices sleep).

### Step 2 — Fast port sweep (masscan)
```bash
./02_scan/recon.sh masscan
```
Rate: 500 pps — safe for fragile IoT. Shows ALL open TCP ports across the subnet in ~2 min.

### Step 3 — Per-host: port scan + OS fingerprint

**CVE targets first** (these feed directly into the exploit phase):
```bash
./02_scan/recon.sh all 10.100.101.10   # Tapo C200       → CVE-2026-1871, CVE-2021-4045, CVE-2025-14300
./02_scan/recon.sh all 10.100.101.12   # Amcrest IP2M    → CVE-2020-5735, CVE-2020-5736
./02_scan/recon.sh all 10.100.101.41   # Tapo L530       → CVE-2023-38907 (also .34 .42 .43 .44 .45)
./02_scan/recon.sh all 10.100.101.55   # Meross MSG100   → CVE-2021-35067
./02_scan/recon.sh all 10.100.101.56   # Reolink D340W   → CVE-2025-55637
./02_scan/recon.sh all 10.100.101.39   # Shelly Plug S   → CVE-2026-64823 (HA XSS)
./02_scan/recon.sh all 10.100.101.40   # Shelly2PM Gen4  → CVE-2026-64823 (HA XSS)
```

**Then remaining devices:**
```bash
./02_scan/recon.sh all 10.100.101.19   # TC70 camera
./02_scan/recon.sh all 10.100.101.20   # Reolink E1 camera
./02_scan/recon.sh all 10.100.101.28   # Alexa Echo Dot
./02_scan/recon.sh all 10.100.101.57   # Fire TV 4K  ← check ADB port 5555!
./02_scan/recon.sh all 10.100.101.11   # ESP sensor .11
./02_scan/recon.sh all 10.100.101.21   # ESP sensor .21
./02_scan/recon.sh all 10.100.101.23   # ESP sensor .23
```

### Step 4 — Vulnerability scan (CVE targets only)
```bash
./02_scan/recon.sh vuln 10.100.101.10
./02_scan/recon.sh vuln 10.100.101.12
./02_scan/recon.sh vuln 10.100.101.56
```

---

## What to look for per device

| Device | IP | Key ports to find | Feeds |
|--------|----|-------------------|-------|
| Tapo C200 | `.10` | 554 (RTSP), 80/443 (HTTP/S) | CVE-2026-1871, brute RTSP |
| Amcrest IP2M | `.12` | **37777** (DHIP), 80, 2020 (ONVIF) | CVE-2020-5735/5736, brute |
| Tapo L530 ×6 | `.34 .41-.45` | 9999 (UDP Tapo) | CVE-2023-38907 replay |
| Meross MSG100 | `.55` | 80 (HTTP), MQTT | CVE-2021-35067 replay |
| Reolink D340W | `.56` | 80, 443, 9000 | CVE-2025-55637, brute |
| Shelly Plug/2PM | `.39 .40` | 80 (HTTP RPC) | CVE-2026-64823, web |
| Fire TV 4K | `.57` | **5555 (ADB!)** | Strong lateral pivot |
| ESP sensors | `.11 .21 .23` | 80, 6053 (ESPHome) | Web fingerprint |
| Echo Dot | `.28` | 4070, 8080 | MITM, lateral |

---

## After the session

```bash
# Label results (do this for each run folder that had interesting findings)
echo "success" > ~/master-thesis/runs/scan/<folder>/result

# Assemble dataset
./dataset/assemble.sh

# Bring tunnel down
sudo wg-quick down fordaysec
```

---

## Evidence location

All scan output → `~/master-thesis/runs/scan/`  
Each run folder contains: `cmd.txt`, `stdout.txt`, nmap `.nmap/.gnmap/.xml` files.
