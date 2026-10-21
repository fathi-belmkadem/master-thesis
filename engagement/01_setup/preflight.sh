#!/usr/bin/env bash
# Verify the tunnel is up, the gateway answers, and ALL required tools exist — before any active phase.
. "$(dirname "$0")/../lib.sh"

fail=0
ok() { echo "  [ok] $1"; }
miss() { echo "  [--] $1 missing"; fail=1; }

echo "== WireGuard interface =="
if sudo wg show fordaysec >/dev/null 2>&1; then
  sudo wg show fordaysec | sed 's/^/  /'
else
  echo "  [!] fordaysec interface not up — run: sudo wg-quick up fordaysec"; fail=1
fi

echo "== Gateway reachability (${GATEWAY}) =="
if ping -c 2 -W 2 "$GATEWAY" >/dev/null 2>&1; then
  ok "gateway ${GATEWAY} replies — tunnel path works"
else
  echo "  [!] no reply from gateway — tunnel not carrying traffic"; fail=1
fi

echo "== Scan phase =="
for t in nmap fping masscan; do
  command -v "$t" >/dev/null 2>&1 && ok "$t" || miss "$t"
done

echo "== Web phase =="
for t in nikto sqlmap whatweb curl; do
  command -v "$t" >/dev/null 2>&1 && ok "$t" || miss "$t"
done

echo "== Brute-force phase =="
for t in hydra medusa; do
  command -v "$t" >/dev/null 2>&1 && ok "$t" || miss "$t"
done

echo "== CVE-exploit phase =="
for t in python3 searchsploit msfconsole; do
  command -v "$t" >/dev/null 2>&1 && ok "$t" || miss "$t"
done
python3 -c "import scapy, packaging, requests" 2>/dev/null \
  && ok "python3 modules (scapy, packaging, requests)" \
  || { echo "  [--] python3 modules missing — run: pip3 install scapy packaging requests"; fail=1; }

echo "== C2 phase =="
command -v sliver >/dev/null 2>&1 && ok "sliver" || echo "  [--] sliver missing (install per upstream docs)"

echo "== DoS phase =="
for t in hping3 slowhttptest; do
  command -v "$t" >/dev/null 2>&1 && ok "$t" || miss "$t"
done

echo "== Exfil phase =="
for t in ssh scp iodine; do
  command -v "$t" >/dev/null 2>&1 && ok "$t" || miss "$t"
done

echo "== MITM phase =="
for t in bettercap tcpdump; do
  command -v "$t" >/dev/null 2>&1 && ok "$t" || miss "$t"
done

echo "== Lateral phase =="
for t in proxychains4 msfconsole; do
  command -v "$t" >/dev/null 2>&1 && ok "$t" || miss "$t"
done

echo "== Inventory =="
n=$(scope_ips | grep -c . || true)
echo "  ${n} target IPs loaded from 00_scope/targets.csv"

echo "== Scripts executable =="
for s in \
  02_scan/recon.sh \
  05_cve_exploit/exploit.sh \
  05_cve_exploit/ha_xss.sh \
  06_c2/c2.sh \
  07_dos_ddos/dos.sh \
  08_exfil/exfil.sh \
  09_mitm/mitm.sh \
  10_lateral/lateral.sh; do
  [[ -x "${ENG_ROOT}/${s}" ]] && ok "$s" || { echo "  [--] $s not executable — run: chmod +x engagement/${s}"; fail=1; }
done

[[ $fail -eq 0 ]] && echo -e "\nPREFLIGHT OK" || { echo -e "\nPREFLIGHT INCOMPLETE — fix the [!]/[--] items first"; exit 1; }
