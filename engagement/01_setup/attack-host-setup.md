# Attack-host setup (Linux)

Target: a Debian/Ubuntu/Kali box that will reach the testbed over WireGuard.
Run these once, then verify the tunnel before any scanning.

## 1. WireGuard tunnel (from `Fathi Config.rtf`)

```bash
sudo apt-get update
sudo apt-get install -y wireguard wireguard-tools

# generate your keypair (public key goes to the supervisor to be added as a peer)
mkdir -p ~/fordaysec && cd ~/fordaysec
umask 077
wg genkey | tee private.key | wg pubkey > public.key
chmod 600 private.key ; chmod 644 public.key
cat public.key        # <-- SEND this to the supervisor; wait until confirmed added
```

Create the client config (matches the supervisor's file):

```bash
umask 077
sudo tee /etc/wireguard/fordaysec.conf > /dev/null <<EOF
[Interface]
PrivateKey = $(cat ~/fordaysec/private.key)
Address = 10.100.101.60/32
MTU = 1420

[Peer]
PublicKey = HDnxoKzDeW2eX6hFmtwp/YUVIova5YjUFeL+wg87Aw0=
Endpoint = 195.37.127.2:15201
PersistentKeepalive = 25
AllowedIPs = 10.100.101.0/24
EOF
sudo chmod 600 /etc/wireguard/fordaysec.conf
```

## 2. Bring it up & verify

```bash
sudo wg-quick up fordaysec
ping -c 3 10.100.101.1     # replies from the gateway = success
sudo wg show fordaysec     # a recent handshake = working
```

Bring it down when done: `sudo wg-quick down fordaysec`

> Note: the config's `AllowedIPs = 10.100.101.0/24` means **only** testbed traffic goes through
> the tunnel; your normal internet keeps working. Good — it also enforces scope at the routing layer.

## 3. Toolchain (grouped by phase)

```bash
# scan
sudo apt-get install -y nmap masscan fping
# (optional) vuln scanners referenced in the catalogue:
#   nuclei  -> install via the project's own installer; OpenVAS/GVM is a separate heavy setup
# web
sudo apt-get install -y nikto sqlmap
#   OWASP ZAP / Burp Suite: install from vendor (GUI); zaproxy pkg also exists
# brute_force
sudo apt-get install -y hydra medusa ncrack
# cve_exploit
sudo apt-get install -y metasploit-framework     # (Kali has it preinstalled)
# c2  -> Sliver / Covenant installed per their own docs (lab-internal only)
# dos/ddos
sudo apt-get install -y hping3 slowhttptest       # slowloris/golang-httpflood: fetch separately
# exfil
sudo apt-get install -y curl openssh-client iodine
# mitm
sudo apt-get install -y ettercap-text-only bettercap tcpdump
```

Not everything above is on stock apt repos (nuclei, Sliver, Covenant, golang-httpflood). Install those
per their upstream instructions **inside the lab host only**. Kali ships most of the rest.

## 4. Sanity check before scanning

```bash
cd /path/to/engagement
./01_setup/preflight.sh     # checks tunnel is up, gateway reachable, required tools present
```
