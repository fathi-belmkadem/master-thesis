# 09_mitm — Man-in-the-Middle

**Script:** `mitm.sh`  
**Session label:** `mitm`  
**ATT&CK:** T1557.002 (ARP Cache Poisoning), T1557 (Adversary-in-the-Middle), T1040 (Network Sniffing)  
**Kill-chain phase:** Delivery (positioning)

## Overview

Positions the attack host on the L2 path between a target device and the gateway by poisoning ARP caches. Once in position, traffic can be intercepted for sniffing or for the session-replay CVEs (05_cve_exploit l530 / meross). DNS spoofing is layered on top.

**This phase is a precondition for:**
- `05_cve_exploit/exploit.sh l530` (CVE-2023-38907)
- `05_cve_exploit/exploit.sh meross` (CVE-2021-35067)

## Scope rule

The gateway (`10.100.101.1`) is **never** a poisoning target. The script validates this. ARP poisoning is limited to the named target device.

## Usage

```bash
# 1. Position on the link (ARP poison target <-> gateway)
./09_mitm/mitm.sh arp   10.100.101.20        # Tapo L530

# 2. (Optional) DNS spoofing on top — redirect a domain to attack host
./09_mitm/mitm.sh dns   10.100.101.20  n8n.io  10.100.101.60

# 3. Passive sniff only (no poisoning)
./09_mitm/mitm.sh sniff 10.100.101.10  60    # 60-second pcap

# 4. Stop all MITM and restore ARP tables
./09_mitm/mitm.sh stop
```

## How it works

| Sub-command | Tool | What happens |
|---|---|---|
| `arp` | bettercap `arp.spoof` | Sends gratuitous ARPs to target and gateway, inserting attack host MAC for both. IP forwarding enabled to maintain connectivity. |
| `dns` | bettercap `dns.spoof` | Replies to DNS queries from target with a spoofed IP for the configured domain. |
| `sniff` | tcpdump on `fordaysec` | Captures all tunnel-side traffic to/from the target without active poisoning. |
| `stop` | `pkill bettercap` | Kills bettercap (which sends ARP restores on exit); disables IP forwarding. |

## Interface name

The WireGuard interface is `fordaysec`. If your interface name differs, set `WG_IFACE=<name>` before running.

## Evidence

Runs write to `runs/mitm/<ts>_<target>/`:
- `cmd.txt` — bettercap command
- `bettercap.log` — bettercap event log (credentials, HTTP headers seen)
- `arp_spoof.cap` / `dns_spoof.cap` — bettercap caplet used
- `sniff.pcap` — passive capture
- `result` — add manually

## Detection signatures

- **ARP**: Gratuitous ARPs with unexpected MAC address; duplicate entries in `arp -a` on target.
- **DNS**: DNS response with an IP different from the legitimate A record.
- **General**: `bettercap` visible in `ps aux` on attack host; IP forwarding (`/proc/sys/net/ipv4/ip_forward` = 1).
