# 03_web — Web attacks (session label: `web`)

Kill-chain: **Delivery → Exploitation → Installation**. Targets are the HTTP(S)/ONVIF web interfaces
surfaced in `02_scan`. ATT&CK: T1190 (exploit public-facing app), T1059 (command injection),
T1505.003 (web shell = Installation).

Driver: [`web.sh`](web.sh). GUI tools (OWASP ZAP, Burp Suite) are used
interactively for XSS / manual command-injection / auth-bypass per the catalogue — log those by
exporting the session + a screenshot into the run folder.

## Candidate targets (from device classes with web UIs)

- **IP cameras** — richest surface: Amcrest `.12` (web `V3.2.1.18144`, ONVIF 21.12), Reolink E1 `.20`,
  Reolink D340W `.56`, Tapo C200 `.10`, TC70 `.19`. Look for: login pages (→ `brute_force`), CGI
  endpoints, firmware-version-specific CVEs, directory traversal, unauthenticated snapshot/RTSP URLs.
- **Shelly plugs** `.39` `.40` — full local web UI + RPC API; check for unauthenticated RPC methods,
  settings changes without auth, OTA endpoints.
- **ESP temp sensors** `.11/.21/.23` — custom firmware (ESPHome/Tasmota-style) web UI; check for
  unauthenticated config/control endpoints and exposed OTA.
- **Tapo/TP-Link plugs & bulbs** — local app protocol on 80 (not a classic browser UI); handle via the
  `cve_exploit`/replay phase rather than nikto.

## Workflow per target

```bash
# 1. fingerprint the stack (server, framework, versions)
./03_web/web.sh fp 10.100.101.12 80 http

# 2. automated misconfig / known-file / dangerous-method scan
./03_web/web.sh nikto 10.100.101.12 80 http

# 3. both schemes at once
./03_web/web.sh survey 10.100.101.12

# 4. if a parameterised endpoint is found, probe it for SQLi (batch, conservative)
./03_web/web.sh sqlmap "http://10.100.101.12/cgi-bin/foo?id=1"

# 5. XSS / command injection / auth bypass / path traversal / malicious upload:
#    drive manually through ZAP or Burp, proxy at 127.0.0.1:8080, export session + screenshots to the run folder.
```

- `nikto -Tuning 123b` targets interesting-files/misconfig/info-disclosure + software ID. Widen tuning
  only deliberately — some checks can trip fragile firmware.
- **Installation (web shell)** belongs here too: only attempt an upload/web-shell where recon showed a
  writable/upload endpoint, and document the exact placement + the removal step (no residue left behind).

### Findings
_(one line per confirmed issue: target | endpoint | issue | ATT&CK ID | evidence path)_
