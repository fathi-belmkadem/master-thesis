# 07_dos_ddos — Denial of Service

**Script:** `dos.sh`  
**Session label:** `dos`  
**ATT&CK:** T1498.001 (Direct Network Flood), T1499 (Endpoint DoS)  
**Kill-chain phase:** Actions on Objectives

## Overview

Volume-based (network-layer) and application-layer denial-of-service against individual lab devices. Four vectors: SYN flood, UDP flood, ICMP flood, HTTP slow exhaustion.

## Safety rules (enforced in script)

1. **One device at a time.** Never flood multiple targets simultaneously.
2. **Short duration.** Default `DOS_DURATION=30` seconds — enough to measure packet loss and latency spike, not long enough to permanently damage hardware.
3. **Verify recovery** with `./01_setup/preflight.sh` after every run before moving to the next device.
4. **Adjust** `DOS_DURATION` if needed:  `DOS_DURATION=60 ./07_dos_ddos/dos.sh syn <ip>`

## Usage

```bash
# SYN flood (exhausts TCP half-open connection table)
./07_dos_ddos/dos.sh syn  10.100.101.10        # 30 s default
./07_dos_ddos/dos.sh syn  10.100.101.10  15    # 15 s

# UDP flood (saturates receive buffer / uplink)
./07_dos_ddos/dos.sh udp  10.100.101.10

# ICMP flood (ICMP handler overload)
./07_dos_ddos/dos.sh icmp 10.100.101.10

# HTTP slowloris / slow-read (app-layer; no bandwidth needed)
./07_dos_ddos/dos.sh http 10.100.101.10 80     # port defaults to 80
```

## Techniques

| Sub-command | Tool | ATT&CK | Effect |
|---|---|---|---|
| `syn` | hping3 `-S --flood` | T1498.001 | Fills half-open connection table; device stops accepting new TCP |
| `udp` | hping3 `--udp --flood` | T1498.001 | Saturates UDP receive queue; device UI / API unresponsive |
| `icmp` | hping3 `--icmp --flood` | T1498.001 | ICMP handler overloaded; ping RTT spikes >1000 ms |
| `http` | slowhttptest `-H` / `-B` | T1499 | Exhausts HTTP connection pool; web UI returns 503 with 0 Bps bandwidth |

## Evidence

Runs write to `runs/dos/<ts>_<ip>/`:
- `cmd.txt` — exact command
- `stdout.txt` — hping3 / slowhttptest output + pre/post ping
- `slowhttp*.html` (slowhttptest HTML report)
- `result` — add manually: `success` (device unreachable during attack), `partial`, `fail`

## Detection signatures

- **SYN**: `netstat -an` shows large `SYN_RECV` backlog; RST storm from device.
- **UDP**: High receive-queue drops in `/proc/net/udp`; device stops responding.
- **ICMP**: Ping RTT >500 ms; ICMP error packets from device.
- **HTTP slowloris**: Server connection count at `MaxClients`; no data transfer but sockets held open for minutes.
