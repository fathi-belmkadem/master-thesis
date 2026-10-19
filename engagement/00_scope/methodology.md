# Methodology — ATT&CK + Kill Chain mapping

The engagement follows the Lockheed Martin Cyber Kill Chain, executed in order, with each
technique mapped to MITRE ATT&CK (Enterprise) exactly as the supervisor's catalogue specifies.
Work one kill-chain phase at a time so the thesis can report findings phase-by-phase.

## Phase order & session categories

| # | Kill-chain phase | Session label(s) | Techniques (from catalogue) | Primary ATT&CK IDs |
|---|------------------|------------------|-----------------------------|--------------------|
| 1 | Reconnaissance | `scan` | host discovery, port/service/version scan, OS/firmware fingerprint, vuln scan | T1595.001, T1046, T1595, T1595.002 |
| 2 | Weaponization | *(offline on attacker host)* | exploit/payload prep | — |
| 3 | Delivery | `mitm` (positioning), `web` | position for MITM; deliver request/exploit to exposed service | T1557, T1190 |
| 4 | Exploitation | `web`, `brute_force`, `cve_exploit` | XSS, SQLi, cmd injection, auth-bypass/traversal, dictionary brute force, credential stuffing, CVE PoCs | T1190, T1059, T1110.001, T1110.004, T1212, T1557 |
| 5 | Installation | `web` | web shell / backdoor / implant placement | T1505.003 |
| 6 | Command & Control | `c2` | beaconing from controlled implant | T1071, T1571 |
| 7 | Actions on Objectives | `dos`/`ddos`, `exfil`, `mitm`, `lateral` | floods, exhaustion, exfil, MITM interception, lateral pivot + internal recon | T1498.001, T1499, T1041, T1048, T1557.002, T1040, T1210, T1021, T1046 |

## Named CVEs in scope (cve_exploit)

| CVE | Target device(s) | Effect | Tool |
|-----|------------------|--------|------|
| CVE-2026-1871 | Tapo C200 (`.10`) | RTSP auth buffer overflow → DoS | Metasploit / custom PoC |
| CVE-2020-5735 | Amcrest IP2M-841B (`.12`) | port 37777 buffer overflow → DoS/RCE | Metasploit / custom PoC |
| CVE-2023-38907 | Tapo L530E (all L530) | session-message replay | bettercap + replay |
| CVE-2021-35067 | Meross MSG100 (`.55`) | capture-replay auth bypass → actuate | bettercap + replay |

## Evidence convention (thesis-grade reproducibility)

For **every** run, capture enough to reproduce and cite it:

1. **Marker** — append `START <label> <target> <ISO8601>` / `STOP ...` to `runs/markers.log`.
2. **Command** — exact command line saved to the per-run folder (`runs/<label>/<timestamp>_<target>/cmd.txt`).
3. **Raw output** — tool stdout/stderr + native output (e.g. nmap `-oA`, pcap) in that folder.
4. **Pre/post state** — for anything that can change device state (cve/dos/mitm/exfil), a short note of device status before and after, plus recovery steps taken.
5. **Observation** — one-line result + the ATT&CK ID, for later aggregation into the results chapter.

Each phase folder's script implements 1–3 automatically. 4–5 are recorded by you per run in `notes.md`.

## Reporting structure (maps to thesis chapters)

- Per category folder (`02_scan` … `10_lateral`) holds: the plan, the commands run, raw evidence, and a findings summary.
- `runs/` holds the machine-generated, timestamped artefacts referenced by those summaries.
