# Scope & Rules of Engagement

> Master thesis — controlled IoT attack simulation against an institutionally approved, isolated testbed.
> Source of truth: `RedTeam_Summary of Attacks.docx` (supervisor) + `Fathi Config.rtf` (VPN).

## Authorization

- All activity is performed **only** against the author's own devices in an **isolated, institutionally approved testbed**.
- **No third party** is targeted. **No live self-propagating malware** is deployed.
- Access is **exclusively via the WireGuard tunnel**. Nothing is launched outside `10.100.101.0/24`.
- Keep the supervisor's written approval / testbed booking reference with this file before any active phase.

## Networks

| Role | Range / host | Notes |
|------|--------------|-------|
| Attacker position (VPN tunnel addr) | `10.100.101.60/32` | Your WireGuard interface `fordaysec` |
| Attacker LAN (per catalogue) | `10.21.40.58 – .62` | Origin stated in the attack doc |
| Target subnet (over tunnel) | `10.100.101.0/24` | Reach each device at its WireGuard IP |
| Target subnet (native/private) | `10.21.30.0/24` | Same devices, lab-side addresses |
| WireGuard gateway | `195.37.127.2:15201` | Peer pubkey `HDnxoKzDeW2eX6hFmtwp/YUVIova5YjUFeL+wg87Aw0=` |
| Gateway ping check | `10.100.101.1` | Reply = tunnel up |

**Reach targets at `10.100.101.X`, where `X` is the last octet of the device's `10.21.30.X` address.**

## In scope

- The 40 devices in `targets.csv` (cameras, plugs, bulbs, motion/humidity sensors, ESP temp sensors, Echo Dot, Fire TV, Meross garage opener).
- The 9 session categories defined by the catalogue: `scan`, `web`, `brute_force`, `cve_exploit`, `c2`, `dos`/`ddos`, `exfil`, `mitm`, `lateral`.

## Out of scope / guardrails

- The WireGuard gateway (`195.37.127.2`) and any transit infrastructure — **do not** attack it; it is only the path in.
- Any address outside `10.100.101.0/24` / `10.21.30.0/24`.
- No persistence that survives the engagement without a documented rollback.
- `dos`/`ddos` and `cve_exploit` DoS cases can brick/hang fragile IoT devices — run them **last per device**, one at a time, with the supervisor informed, and capture a pre-state so recovery (power-cycle/factory-reset) is documented.

## Session marker scheme

The catalogue references the **Home Assistant marker scheme**: each active run is bracketed by a start/stop marker carrying the category label so captured traffic/telemetry can be sliced per attack. Every script here writes a marker line (category label + timestamp + target) to `runs/markers.log` at start and end of a run. See `../01_setup/attack-host-setup.md` and `methodology.md`.
