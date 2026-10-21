# 00_scope — Scope, Inventory & Methodology

This folder contains the three ground-truth documents that govern every action in the engagement.
**Read these before running anything.**

---

## Files

### `scope.md` — Rules of Engagement

Defines:
- **Authorization statement**: all activity is performed only against the author's own devices in an
  institutionally approved, isolated testbed. No third party is targeted.
- **Network ranges**: WireGuard tunnel (`10.100.101.0/24`), lab-side network (`10.21.30.0/24`),
  gateway ping-check address (`10.100.101.1`).
- **In-scope devices**: all 40 devices in `targets.csv`.
- **Out-of-scope guardrails**: gateway, transit infra, anything outside `10.100.101.0/24`.
- **Session marker scheme**: how `lib.sh` markers map to Home Assistant labels.

### `targets.csv` — Device Inventory

40 lab devices, one row per device:

| Column | Example | Notes |
|--------|---------|-------|
| `device_model` | Tapo C200 | Vendor + model as on device label |
| `private_ip` | 10.21.30.10 | Lab-side address (for reference) |
| `wireguard_ip` | 10.100.101.10 | **Use this** from the attack host |
| `mac` | ec:75:0c:4e:e9:a6 | From ARP / DHCP |
| `firmware` | V1.3.3 | As reported by device UI |
| `device_class` | ip_camera | One of 10 classes (see below) |

**Device classes** in the inventory:

| Class | Count | Examples |
|-------|-------|---------|
| `ip_camera` | 5 | Tapo C200, Amcrest IP2M-841B-V3, Reolink E1, Reolink D340W, TC70 |
| `smart_plug` | 6 | Shelly Plug S, Shelly2PM, Tapo P125M, P100, P115 |
| `smart_bulb` | 8 | Tapo L530 (×6), TP-L900, H6008 E27 |
| `motion_sensor` | 6 | ZY-M100 (×2), PIR P01 (×4) |
| `esp_sensor` | 3 | Piotek EspTempsensor (×3) |
| `appliance` | 1 | Govee H714E (×3) / H5179 (×2) |
| `sensor` | 1 | (humidity/temp sensors) |
| `voice_assistant` | 1 | Amazon Echo Dot |
| `media_device` | 1 | Amazon Fire TV 4K |
| `garage_opener` | 1 | Meross MSG100 |

### `methodology.md` — Kill-Chain & Evidence Convention

Defines:
- **Phase order**: how the kill-chain phases map to engagement folders.
- **ATT&CK IDs**: the specific technique IDs for each phase and sub-technique.
- **CVE table**: the 4 original CVEs from the supervisor's catalogue (now expanded to 9 in `05_cve_exploit/`).
- **Evidence convention**: what each run folder must contain (`cmd.txt`, `stdout.txt`, `result`, `notes.md`).

---

## Key Numbers

| Item | Value |
|------|-------|
| Attack host WireGuard IP | `10.100.101.60/32` |
| WireGuard interface name | `fordaysec` |
| Target subnet (tunnel) | `10.100.101.0/24` |
| Gateway (ping-check only, not a target) | `10.100.101.1` |
| WireGuard endpoint (supervisor's server) | `195.37.127.2:15201` |
| Total lab devices | 40 |
| CVEs in scope | 9 (see `05_cve_exploit/README.md`) |

---

## Using the Inventory in Scripts

```bash
# lib.sh helper: iterate over all in-scope WireGuard IPs
. ./lib.sh
for ip in $(scope_ips); do
  echo "Target: $ip"
done

# Or use awk to filter by device class:
awk -F, '$6=="ip_camera" {print $3}' 00_scope/targets.csv
```
