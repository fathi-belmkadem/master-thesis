#!/usr/bin/env bash
# Phase 1 — Reconnaissance (session label: scan)
# Runs the four scan sub-types from the catalogue against in-scope targets only,
# with HA-style markers and reproducible, timestamped evidence under runs/scan/.
#
# Usage (from the engagement root):
#   ./02_scan/recon.sh discovery                 # host discovery / ping sweep (whole subnet)
#   ./02_scan/recon.sh ports       <ip> [ip...]  # SYN + service/version scan
#   ./02_scan/recon.sh fingerprint <ip> [ip...]  # OS/firmware fingerprint
#   ./02_scan/recon.sh vuln        <ip> [ip...]  # nmap --script vuln
#   ./02_scan/recon.sh all         <ip> [ip...]  # ports + fingerprint + vuln per host
#   ./02_scan/recon.sh all-inventory             # all sub-types across every inventory IP
#
# ATT&CK: T1595.001 (discovery), T1046 (ports), T1595 (fingerprint), T1595.002 (vuln)
. "$(dirname "$0")/../lib.sh"

LABEL=scan
NMAP_TIMING="-T3"   # polite-ish: fragile IoT devices can drop under aggressive timing

do_discovery() {
  local dir; dir=$(new_run "$LABEL" "subnet")
  local cmd="sudo nmap -sn ${NMAP_TIMING} ${SCOPE_CIDR_PREFIX}0/24 --exclude ${GATEWAY} -oA ${dir}/discovery"
  save_cmd "$dir" "$cmd"; echo "+ $cmd"
  sudo nmap -sn ${NMAP_TIMING} "${SCOPE_CIDR_PREFIX}0/24" --exclude "${GATEWAY}" \
    -oA "${dir}/discovery" | tee "${dir}/stdout.txt"
  end_run "$LABEL" "subnet"
  echo ">> evidence: $dir"
}

do_ports() {
  require_scope "$@"
  for ip in "$@"; do
    local dir; dir=$(new_run "$LABEL" "$ip")
    local cmd="sudo nmap -sS -sV -p- ${NMAP_TIMING} ${ip} -oA ${dir}/tcp_ports && sudo nmap -sU --top-ports 50 ${NMAP_TIMING} ${ip} -oA ${dir}/udp_ports"
    save_cmd "$dir" "$cmd"; echo "+ $cmd"
    sudo nmap -sS -sV -p- ${NMAP_TIMING} "$ip" -oA "${dir}/tcp_ports" | tee "${dir}/stdout.txt"
    sudo nmap -sU --top-ports 50 ${NMAP_TIMING} "$ip" -oA "${dir}/udp_ports" | tee -a "${dir}/stdout.txt"
    end_run "$LABEL" "$ip"; echo ">> evidence: $dir"
  done
}

do_fingerprint() {
  require_scope "$@"
  for ip in "$@"; do
    local dir; dir=$(new_run "$LABEL" "$ip")
    local cmd="sudo nmap -O --osscan-guess ${NMAP_TIMING} ${ip} -oA ${dir}/osfp"
    save_cmd "$dir" "$cmd"; echo "+ $cmd"
    sudo nmap -O --osscan-guess ${NMAP_TIMING} "$ip" -oA "${dir}/osfp" | tee "${dir}/stdout.txt"
    end_run "$LABEL" "$ip"; echo ">> evidence: $dir"
  done
}

do_vuln() {
  require_scope "$@"
  for ip in "$@"; do
    local dir; dir=$(new_run "$LABEL" "$ip")
    local cmd="sudo nmap -sV --script vuln ${NMAP_TIMING} ${ip} -oA ${dir}/vuln"
    save_cmd "$dir" "$cmd"; echo "+ $cmd"
    sudo nmap -sV --script vuln ${NMAP_TIMING} "$ip" -oA "${dir}/vuln" | tee "${dir}/stdout.txt"
    end_run "$LABEL" "$ip"; echo ">> evidence: $dir"
  done
}

cmd="${1:-}"; shift || true
case "$cmd" in
  discovery)      do_discovery ;;
  ports)          do_ports "$@" ;;
  fingerprint)    do_fingerprint "$@" ;;
  vuln)           do_vuln "$@" ;;
  all)            do_ports "$@"; do_fingerprint "$@"; do_vuln "$@" ;;
  all-inventory)  mapfile -t ips < <(scope_ips); do_ports "${ips[@]}"; do_fingerprint "${ips[@]}"; do_vuln "${ips[@]}" ;;
  *) sed -n '2,20p' "$0"; exit 1 ;;
esac
