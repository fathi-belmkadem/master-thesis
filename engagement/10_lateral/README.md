# 10_lateral — Lateral Movement

**Script:** `lateral.sh`  
**Session label:** `lateral`  
**ATT&CK:** T1210 (Exploitation of Remote Services), T1021 (Remote Services), T1046 (Network Scan)  
**Kill-chain phase:** Lateral Movement

## Overview

Uses a compromised IoT device as a pivot to reach devices in network segments not directly accessible from the attack host. Two pivot mechanisms: Metasploit route (with a Meterpreter session) and Sliver SOCKS5 proxy (with a Sliver beacon). A ProxyJump SSH chain is also included for direct lateral SSH hops.

## Prerequisites

- Active foothold on the pivot device: either a Sliver beacon (`06_c2/c2.sh beacon`) or a Metasploit Meterpreter session.
- Target segment is reachable from the pivot but not from the attack host directly.

## Usage

```bash
# 1. Set up a Metasploit route through a compromised pivot
./10_lateral/lateral.sh pivot  10.100.101.10

# 2. Scan the internal subnet through the pivot
./10_lateral/lateral.sh recon  10.100.101.10  192.168.1.0/24

# 3. SSH lateral hop: attack -> pivot -> next device
SSH_USER=admin ./10_lateral/lateral.sh ssh  10.100.101.10  192.168.1.5
```

## Sliver alternative (recommended if using 06_c2)

Once a Sliver beacon is active on the pivot, open a SOCKS5 tunnel:

```
# In sliver-client:
sliver > use <beacon-id>
sliver (lab_beacon) > socks5 start --host 127.0.0.1 --port 1080
```

Then `recon` sub-command automatically uses `proxychains4` if available, routing nmap through the SOCKS5 tunnel.

Configure proxychains:
```
# /etc/proxychains4.conf — append:
socks5 127.0.0.1 1080
```

## Evidence

Runs write to `runs/lateral/<ts>_<pivot>/`:
- `cmd.txt` — exact commands
- `stdout.txt` — scan / SSH output
- `pivot_setup.rc` / `lateral_scan.rc` — Metasploit resource scripts
- `result` — add manually

## Detection signatures

- **Pivot route**: New TCP connections originating from the pivot's IP to other internal hosts (unusual lateral traffic).
- **SOCKS5**: Proxied nmap traffic exits from the pivot's interface rather than the attack host.
- **SSH hop**: SSH session from pivot to next target (unexpected SSH source in auth logs).
- **General**: `proxychains4` / `route print` in Metasploit session reveals attacker's lateral reachability.
