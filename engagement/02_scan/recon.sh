#!/usr/bin/env bash
# Phase 02 — Reconnaissance  (session label: scan)
# ══════════════════════════════════════════════════════════════
# All scans target only the approved WireGuard subnet (10.100.101.0/24).
# Gateway 10.100.101.1 is infra — reachability check only, never targeted.
# Timing is kept at -T3; IoT devices can wedge under -T4/-T5.
#
# Usage (from the engagement root):
#   ./02_scan/recon.sh session              ← professor session: full pipeline, all hosts
#   ./02_scan/recon.sh discovery            ← ping sweep (who is alive?)
#   ./02_scan/recon.sh masscan              ← fast TCP port sweep of whole subnet
#   ./02_scan/recon.sh ports       <ip...>  ← full TCP + top-50 UDP, service/version
#   ./02_scan/recon.sh fingerprint <ip...>  ← OS + firmware fingerprint
#   ./02_scan/recon.sh vuln        <ip...>  ← nmap vuln scripts
#   ./02_scan/recon.sh all         <ip...>  ← ports + fingerprint + vuln on one host
#   ./02_scan/recon.sh all-inventory        ← all sub-types across every inventory IP
#
# ATT&CK: T1595.001 (discovery), T1046 (ports), T1595 (fingerprint), T1595.002 (vuln)
# ══════════════════════════════════════════════════════════════
. "$(dirname "$0")/../lib.sh"

LABEL=scan
NMAP_TIMING="-T3"
SUBNET="${SCOPE_CIDR_PREFIX}0/24"

# ── 1. Ping sweep ─────────────────────────────────────────────
do_discovery() {
  local dir; dir=$(new_run "$LABEL" "subnet")
  echo "[*] Host discovery — ping sweep of ${SUBNET} (excluding gateway ${GATEWAY})"
  local cmd="sudo nmap -sn ${NMAP_TIMING} ${SUBNET} --exclude ${GATEWAY} -oA ${dir}/discovery"
  save_cmd "$dir" "$cmd"; echo "+ $cmd"
  sudo nmap -sn ${NMAP_TIMING} "${SUBNET}" --exclude "${GATEWAY}" \
    -oA "${dir}/discovery" | tee "${dir}/stdout.txt"
  end_run "$LABEL" "subnet"
  echo ">> evidence: $dir"
  echo
  echo "[*] Live hosts:"
  grep "report for" "${dir}/discovery.gnmap" 2>/dev/null | awk '{print $5}' || true
}

# ── 2. Fast port sweep (masscan) ─────────────────────────────
do_masscan() {
  local dir; dir=$(new_run "$LABEL" "masscan")
  echo "[*] masscan — fast TCP sweep of all 65535 ports on ${SUBNET}"
  echo "    Rate 500 pps (safe for IoT — do NOT increase, devices may wedge)"
  local cmd="sudo masscan ${SUBNET} -p1-65535 --rate 500 --exclude ${GATEWAY} -oL ${dir}/masscan.txt"
  save_cmd "$dir" "$cmd"; echo "+ $cmd"
  sudo masscan "${SUBNET}" -p1-65535 --rate 500 --exclude "${GATEWAY}" \
    -oL "${dir}/masscan.txt" 2>&1 | tee "${dir}/stdout.txt" || true
  end_run "$LABEL" "masscan"
  echo ">> evidence: $dir"
  echo
  echo "[*] Open ports found:"
  grep "^open" "${dir}/masscan.txt" 2>/dev/null | awk '{print $4, $3}' | sort -V || true
}

# ── 3. Full TCP + UDP port scan with service/version ──────────
do_ports() {
  require_scope "$@"
  for ip in "$@"; do
    local dir; dir=$(new_run "$LABEL" "$ip")
    echo "[*] Port scan: ${ip} — full TCP + top-50 UDP, service + version detection"
    local cmd="sudo nmap -sS -sV -p- ${NMAP_TIMING} ${ip} -oA ${dir}/tcp && sudo nmap -sU --top-ports 50 ${NMAP_TIMING} ${ip} -oA ${dir}/udp"
    save_cmd "$dir" "$cmd"; echo "+ $cmd"
    sudo nmap -sS -sV -p- ${NMAP_TIMING} "$ip" -oA "${dir}/tcp" | tee "${dir}/stdout.txt"
    sudo nmap -sU --top-ports 50 ${NMAP_TIMING} "$ip" -oA "${dir}/udp" | tee -a "${dir}/stdout.txt"
    end_run "$LABEL" "$ip"; echo ">> evidence: $dir"
  done
}

# ── 4. OS + firmware fingerprint ──────────────────────────────
do_fingerprint() {
  require_scope "$@"
  for ip in "$@"; do
    local dir; dir=$(new_run "$LABEL" "$ip")
    echo "[*] OS fingerprint: ${ip}"
    local cmd="sudo nmap -O --osscan-guess -sV ${NMAP_TIMING} ${ip} -oA ${dir}/osfp"
    save_cmd "$dir" "$cmd"; echo "+ $cmd"
    sudo nmap -O --osscan-guess -sV ${NMAP_TIMING} "$ip" -oA "${dir}/osfp" | tee "${dir}/stdout.txt"
    end_run "$LABEL" "$ip"; echo ">> evidence: $dir"
  done
}

# ── 5. Vulnerability scan ─────────────────────────────────────
do_vuln() {
  require_scope "$@"
  for ip in "$@"; do
    local dir; dir=$(new_run "$LABEL" "$ip")
    echo "[*] Vuln scan: ${ip} — nmap vuln scripts + http-* enumeration"
    local cmd="sudo nmap -sV --script vuln,http-enum,http-headers,http-methods ${NMAP_TIMING} ${ip} -oA ${dir}/vuln"
    save_cmd "$dir" "$cmd"; echo "+ $cmd"
    sudo nmap -sV --script "vuln,http-enum,http-headers,http-methods" ${NMAP_TIMING} \
      "$ip" -oA "${dir}/vuln" | tee "${dir}/stdout.txt"
    end_run "$LABEL" "$ip"; echo ">> evidence: $dir"
  done
}

# ── 6. Full pipeline — one host ────────────────────────────────
do_all() {
  require_scope "$@"
  for ip in "$@"; do
    echo "════ ${ip} ════════════════════════════════"
    do_ports      "$ip"
    do_fingerprint "$ip"
    do_vuln        "$ip"
  done
}

# ── 7. Professor session — full recon across all inventory ─────
# Runs the complete pipeline in order and wraps it in an episode
# so the dataset assembler groups it as one trajectory.
#
#   Order:  discovery → masscan → per-host: ports + fingerprint + vuln
#   Time:   ~2-4 h depending on device count and responsiveness
do_session() {
  episode_start "recon_full_$(date -u +%Y%m%d)"
  echo "╔══════════════════════════════════════════════════════╗"
  echo "║  PROFESSOR RECON SESSION — full pipeline, all hosts  ║"
  echo "╚══════════════════════════════════════════════════════╝"

  echo
  echo "── Step 1/4: Host discovery ────────────────────────────"
  do_discovery

  echo
  echo "── Step 2/4: Masscan fast port sweep ───────────────────"
  do_masscan

  echo
  echo "── Step 3/4: Per-host deep scan ────────────────────────"
  mapfile -t ips < <(scope_ips)
  for ip in "${ips[@]}"; do
    echo
    echo "  → ${ip}"
    do_ports       "$ip"
    do_fingerprint "$ip"
  done

  echo
  echo "── Step 4/4: Vulnerability scan ────────────────────────"
  echo "    (running vuln scripts on CVE-target hosts first)"
  local cve_targets=(
    10.100.101.10   # Tapo C200
    10.100.101.12   # Amcrest IP2M-841B-V3
    10.100.101.39   # Shelly Plug S Gen3
    10.100.101.40   # Shelly2PM Gen4
    10.100.101.41   # Tapo L530
    10.100.101.55   # Meross MSG100
    10.100.101.56   # Reolink D340W
  )
  for ip in "${cve_targets[@]}"; do
    do_vuln "$ip"
  done

  episode_stop "recon_full_$(date -u +%Y%m%d)"
  echo
  echo "╔══════════════════════════════════════════════════════╗"
  echo "║  SESSION COMPLETE — evidence under runs/scan/        ║"
  echo "║  Next step: 03_web/web.sh survey <ip>               ║"
  echo "╚══════════════════════════════════════════════════════╝"
}

# ─────────────────────────────────────────────────────────────
cmd="${1:-}"; shift || true
case "$cmd" in
  session)      do_session ;;
  discovery)    do_discovery ;;
  masscan)      do_masscan ;;
  ports)        do_ports "$@" ;;
  fingerprint)  do_fingerprint "$@" ;;
  vuln)         do_vuln "$@" ;;
  all)          do_all "$@" ;;
  all-inventory) mapfile -t ips < <(scope_ips); do_all "${ips[@]}" ;;
  *) sed -n '2,20p' "$0"; exit 1 ;;
esac
