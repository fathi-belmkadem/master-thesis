# 02_scan — Reconnaissance (session label: `scan`)

Kill-chain phase: **Reconnaissance**. Goal: for every device, establish *what it is, what it exposes,
and where it is weak* — the input that drives the `web`, `brute_force`, and `cve_exploit` phases.
ATT&CK: T1595.001 (discovery), T1046 (ports), T1595 (fingerprint), T1595.002 (vuln scan).

Driver: [`recon.sh`](recon.sh). Evidence → `../runs/scan/`.

## Order of operations

1. **Subnet discovery** — who is actually alive right now.
   ```bash
   ./02_scan/recon.sh discovery
   ```
   Cross-check the live hosts against [`../00_scope/targets.csv`](../00_scope/targets.csv). Note any
   device that is *down* (IoT devices sleep / drop off) — you'll want it powered on before its scan.

2. **Per-host port + service/version** — the core of recon.
   ```bash
   ./02_scan/recon.sh ports 10.100.101.10        # one host
   ./02_scan/recon.sh all-inventory              # everything (long; run overnight)
   ```

3. **Fingerprint + vuln** — only after ports, and prioritise by device class (below).
   ```bash
   ./02_scan/recon.sh fingerprint 10.100.101.12
   ./02_scan/recon.sh vuln        10.100.101.12
   ```

> Timing is set to `-T3` in the script on purpose: these are fragile embedded devices and aggressive
> timing (`-T4/-T5`, full `-sU`) can hang or reboot them, which contaminates later phases. If a device
> stops responding mid-scan, record it in the run's `notes.md` — that itself is a finding (fragility).

## What to look for, per device class

The inventory groups into 9 classes (see the `device_class` column). Expected exposure and the
signal that matters for later phases:

| Class | Devices (last octet) | Expect to see | What it feeds |
|-------|----------------------|---------------|---------------|
| **ip_camera** | Tapo C200 `.10`, Amcrest `.12`, TC70 `.19`, Reolink E1 `.20`, Reolink D340W `.56` | RTSP **554**, ONVIF (**2020**/8000/80), HTTP(S) web UI **80/443/8080**, Amcrest proprietary **37777** | `cve_exploit` (CVE-2026-1871 C200 RTSP, CVE-2020-5735 Amcrest 37777), `web`, `brute_force` (RTSP/ONVIF creds) |
| **smart_plug** | Shelly S `.39`, Shelly2PM `.40`, Tapo P125M `.37/.38`, P100 `.36`, P115 `.35` | TP-Link/Tapo local API **80** / legacy Kasa **9999**; Shelly HTTP **80** + RPC/WebSocket, CoAP **5683** | `web` (Shelly RPC/UI), `cve_exploit` (replay), `c2`/`exfil` pivot candidates |
| **smart_bulb** | Tapo L530 `.34/.41/.42/.43/.44/.45`, TP-L900 `.26/.27`, H6008 `.33`, Alantop `.24/.25` | TP-Link local **80/9999**; Govee/Tuya UDP | `cve_exploit` (CVE-2023-38907 L530 replay) |
| **esp_sensor** | Piotek_EspTempsensor `.11/.21/.23` | HTTP **80** (web UI), ESPHome API **6053**, OTA, mDNS | custom firmware → high-value `web` + fingerprint target |
| **motion_sensor** | ZY-M100 `.13/.14`, PIR P01 `.9/.15/.16/.17/.18` | Tuya local **6668** (ZY-M100), minimal TCP on PIR | fingerprint; `mitm` (sensor telemetry) |
| **appliance / sensor** | Govee H714E `.30/.31/.32`, H5179 `.53/.54` | Govee LAN UDP **4001–4003**; mostly cloud | `mitm`, `exfil` observation |
| **voice_assistant** | Echo Dot `.28` | **4070**, 8080, 55442/55443, mDNS | `mitm`, `lateral` |
| **media_device** | Fire TV 4K `.57` | ADB **5555** (if enabled!), DIAL **8008/8009**, 55442 | `lateral`/`c2` (ADB = strong foothold) |
| **garage_opener** | Meross MSG100 `.55` | local HTTP **80**, MQTT, mDNS | `cve_exploit` (CVE-2021-35067 replay → actuate) |

## Per-run finding template

After each scan, append one line here (keeps the results chapter trivial to assemble):

```
<wg_ip>  <device>  | open: <ports/services>  | note: <anything odd>  | feeds: <next phase/CVE>  | evidence: runs/scan/<folder>
```

### Findings
_(fill in as you go)_
