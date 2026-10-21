# 01_setup — Attack Host Setup & Preflight

This folder handles the one-time preparation of the Kali Linux attack host and the
verification check that must be run before every engagement session.

---

## Files

### `attack-host-setup.md` — Full Setup Guide

Step-by-step instructions for preparing the Kali attack host:

1. **WireGuard installation and configuration** — import `Fathi Config.rtf` (the supervisor-provided
   VPN config), bring up the `fordaysec` interface, confirm the tunnel is up.
2. **Tool installation** — all tools used across phases 02–10, grouped by phase:
   - Scan: `nmap`, `masscan`
   - Web: `whatweb`, `nikto`, `sqlmap`, `curl`
   - Brute: `hydra`, `medusa`
   - CVE/exploit: `python3`, `scapy`, `searchsploit`, `metasploit-framework`
   - C2: `sliver`
   - DoS: `hping3`, `slowhttptest`
   - Exfil: `scp` (openssh-client), `iodine`
   - MITM: `bettercap`, `tcpdump`
   - Lateral: `proxychains4`, `nmap` (already installed)
3. **Python dependencies** — `pip3 install scapy packaging requests`
4. **Verification** — run `preflight.sh` to confirm everything is in place.

### `preflight.sh` — Pre-Session Checklist

Run this **before every active session** and **after every DoS or crash test** to confirm
the lab is in a known good state.

Checks performed:
1. WireGuard tunnel is up (`fordaysec` interface exists)
2. Gateway `10.100.101.1` is reachable (ping)
3. All core tools are installed (`nmap`, `hydra`, `python3`, `hping3`, `bettercap`, etc.)
4. `runs/` directory exists (creates it if not)

```bash
./01_setup/preflight.sh
```

Exit codes: `0` = all checks pass; `1` = one or more checks failed (fix before continuing).

---

## Quick Setup (First Time)

```bash
# 1. Install WireGuard
sudo apt update && sudo apt install -y wireguard

# 2. Import config (the .conf file is gitignored — never commit it)
sudo cp /path/to/fathi_config.conf /etc/wireguard/fordaysec.conf
sudo wg-quick up fordaysec

# 3. Verify tunnel
ping -c 3 10.100.101.1

# 4. Install all tools
sudo apt install -y nmap masscan whatweb nikto sqlmap hydra \
  hping3 slowhttptest bettercap tcpdump iodine openssh-client \
  metasploit-framework python3 python3-pip proxychains4
pip3 install scapy packaging requests

# 5. Install Sliver C2
curl https://sliver.sh/install | sudo bash

# 6. Run the preflight check
chmod +x engagement/01_setup/preflight.sh
./engagement/01_setup/preflight.sh
```
