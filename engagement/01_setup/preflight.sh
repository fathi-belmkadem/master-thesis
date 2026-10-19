#!/usr/bin/env bash
# Verify the tunnel is up, the gateway answers, and required tools exist — before any active phase.
. "$(dirname "$0")/../lib.sh"

fail=0

echo "== WireGuard interface =="
if sudo wg show fordaysec >/dev/null 2>&1; then
  sudo wg show fordaysec | sed 's/^/  /'
else
  echo "  [!] fordaysec interface not up — run: sudo wg-quick up fordaysec"; fail=1
fi

echo "== Gateway reachability (${GATEWAY}) =="
if ping -c 2 -W 2 "$GATEWAY" >/dev/null 2>&1; then
  echo "  [ok] gateway replies — tunnel path works"
else
  echo "  [!] no reply from gateway — tunnel not carrying traffic"; fail=1
fi

echo "== Scan-phase tools =="
for t in nmap fping masscan; do
  if command -v "$t" >/dev/null 2>&1; then echo "  [ok] $t"; else echo "  [--] $t missing"; fi
done

echo "== Inventory =="
n=$(scope_ips | grep -c . || true)
echo "  ${n} target IPs loaded from 00_scope/targets.csv"

[[ $fail -eq 0 ]] && echo "PREFLIGHT OK" || { echo "PREFLIGHT INCOMPLETE — fix the [!] items first"; exit 1; }
