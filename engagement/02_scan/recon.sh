#!/usr/bin/env bash
# Phase 02 — Reconnaissance  (session label: scan)
# ══════════════════════════════════════════════════════════════════════
# Targets: 00_scope/targets.txt (professor format — one IP per line, # comments)
# Interface: fordaysec (WireGuard tunnel)
# Gateway 10.100.101.1 — reachability check only, never a target
# Panda-Pivot 10.100.101.4 — pre-compromised foothold, skipped in exploit scans
# Timing: -T3 throughout; IoT devices can crash under -T4/-T5
#
# Usage (from the engagement root):
#   ./02_scan/recon.sh session              ← PROFESSOR SESSION: full pipeline, all targets
#   ./02_scan/recon.sh discovery            ← ping sweep (who is alive?)
#   ./02_scan/recon.sh masscan              ← fast TCP sweep all 65535 ports, all targets
#   ./02_scan/recon.sh ports       <ip...>  ← full TCP + top-50 UDP + service/version
#   ./02_scan/recon.sh fingerprint <ip...>  ← OS + firmware fingerprint
#   ./02_scan/recon.sh vuln        <ip...>  ← nmap vuln + http scripts
#   ./02_scan/recon.sh all         <ip...>  ← ports + fingerprint + vuln on one host
#   ./02_scan/recon.sh all-inventory        ← all sub-types on every inventory IP
#
# ATT&CK: T1595.001 (discovery) T1046 (ports) T1595 (fingerprint) T1595.002 (vuln)
# ══════════════════════════════════════════════════════════════════════
. "$(dirname "$0")/../lib.sh"

LABEL=scan
T="-T3"                         # nmap timing — keep at T3 for IoT safety
IFACE="fordaysec"               # WireGuard interface
SUBNET="${SCOPE_CIDR_PREFIX}0/24"
PIVOT_IP="10.100.101.4"         # Panda-Pivot — foothold host, skip in exploit phases

banner() { echo; echo "── $* ──────────────────────────────────────────────────"; }

# ── 1. Ping sweep (nmap -sn) ──────────────────────────────────
do_discovery() {
  banner "STEP 1/5  Host discovery — ping sweep"
  local dir; dir=$(new_run "$LABEL" "discovery")
  local cmd="sudo nmap -sn $T $SUBNET --exclude $GATEWAY -e $IFACE -oA ${dir}/discovery"
  save_cmd "$dir" "$cmd"; echo "+ $cmd"
  sudo nmap -sn $T "$SUBNET" --exclude "$GATEWAY" -e "$IFACE" \
    -oA "${dir}/discovery" | tee "${dir}/stdout.txt"
  end_run "$LABEL" "discovery"
  echo
  echo "[*] Live hosts:"
  grep "report for" "${dir}/discovery.gnmap" 2>/dev/null | awk '{print "   " $5}' || true
  echo ">> evidence: $dir"
}

# ── 2. Fast TCP sweep (masscan) ───────────────────────────────
do_masscan() {
  banner "STEP 2/5  masscan — all 65535 TCP ports, all targets"
  local dir; dir=$(new_run "$LABEL" "masscan")
  local tfile; tfile=$(targets_file)
  echo "[*] Target list: $(wc -l < "$tfile") IPs from 00_scope/targets.txt"
  echo "[*] Rate: 1000 pps on interface $IFACE (--wait 10 for straggler responses)"
  local cmd="sudo masscan -iL ${tfile} -p1-65535 -e ${IFACE} --rate 1000 --wait 10 -oL ${dir}/masscan.txt"
  save_cmd "$dir" "$cmd"; echo "+ $cmd"
  sudo masscan -iL "$tfile" -p1-65535 -e "$IFACE" \
    --rate 1000 --wait 10 -oL "${dir}/masscan.txt" 2>&1 | tee "${dir}/stdout.txt" || true
  rm -f "$tfile"
  end_run "$LABEL" "masscan"
  echo
  echo "[*] Open ports summary:"
  grep "^open" "${dir}/masscan.txt" 2>/dev/null \
    | awk '{print "   " $4 "\t" $3 "/tcp"}' | sort -V || echo "   (none yet — masscan may still be running)"
  echo ">> evidence: $dir"
}

# ── 3. Full TCP + top-50 UDP, service + version detection ─────
do_ports() {
  require_scope "$@"
  for ip in "$@"; do
    banner "STEP 3  Port scan: $ip"
    local dir; dir=$(new_run "$LABEL" "$ip")
    save_cmd "$dir" "sudo nmap -sS -sV -p- $T $ip -oA ${dir}/tcp  &&  sudo nmap -sU --top-ports 50 $T $ip -oA ${dir}/udp"
    echo "[*] TCP full-port + service/version"
    sudo nmap -sS -sV -p- $T "$ip" -oA "${dir}/tcp" | tee "${dir}/stdout.txt"
    echo "[*] UDP top-50"
    sudo nmap -sU --top-ports 50 $T "$ip" -oA "${dir}/udp" | tee -a "${dir}/stdout.txt"
    end_run "$LABEL" "$ip"; echo ">> evidence: $dir"
  done
}

# ── 4. OS + firmware fingerprint ──────────────────────────────
do_fingerprint() {
  require_scope "$@"
  for ip in "$@"; do
    banner "STEP 4  OS fingerprint: $ip"
    local dir; dir=$(new_run "$LABEL" "$ip")
    local cmd="sudo nmap -O --osscan-guess -sV $T $ip -oA ${dir}/osfp"
    save_cmd "$dir" "$cmd"; echo "+ $cmd"
    sudo nmap -O --osscan-guess -sV $T "$ip" -oA "${dir}/osfp" | tee "${dir}/stdout.txt"
    end_run "$LABEL" "$ip"; echo ">> evidence: $dir"
  done
}

# ── 5. Vulnerability scan ─────────────────────────────────────
do_vuln() {
  require_scope "$@"
  for ip in "$@"; do
    banner "STEP 5  Vuln scan: $ip"
    local dir; dir=$(new_run "$LABEL" "$ip")
    local cmd="sudo nmap -sV --script vuln,http-enum,http-headers,http-methods,http-title $T $ip -oA ${dir}/vuln"
    save_cmd "$dir" "$cmd"; echo "+ $cmd"
    sudo nmap -sV --script "vuln,http-enum,http-headers,http-methods,http-title" \
      $T "$ip" -oA "${dir}/vuln" | tee "${dir}/stdout.txt"
    end_run "$LABEL" "$ip"; echo ">> evidence: $dir"
  done
}

# ── All sub-types on one or more hosts ────────────────────────
do_all() {
  require_scope "$@"
  for ip in "$@"; do
    echo; echo "════ $ip ════════════════════════════════════════════"
    do_ports       "$ip"
    do_fingerprint "$ip"
    do_vuln        "$ip"
  done
}

# ── PROFESSOR SESSION — full pipeline, all targets ────────────
# Runs the complete recon chain in order, wrapped in an episode so
# assemble.py groups it as one trajectory.
#
# Total time: ~3-5 h (full nmap port scan is the bottleneck)
# CVE targets get vuln scan; the rest get ports + fingerprint only.
do_session() {
  local ep_id="recon_$(date -u +%Y%m%d)"
  episode_start "$ep_id"

  echo "╔══════════════════════════════════════════════════════════╗"
  echo "║   PROFESSOR RECON SESSION — $(date -u '+%Y-%m-%d %H:%M UTC')           ║"
  echo "║   Targets: $(scope_ips | wc -l) IPs from 00_scope/targets.txt          ║"
  echo "╚══════════════════════════════════════════════════════════╝"
  echo "[i] Panda-Pivot $PIVOT_IP excluded from exploit scans (pre-compromised foothold)"

  do_discovery
  do_masscan

  # Priority: CVE targets first — these feed directly into 05_cve_exploit
  banner "STEP 3/5  Port + OS scan — CVE targets (priority)"
  local cve_targets=(
    10.100.101.10   # Tapo C200        → CVE-2026-1871 / CVE-2021-4045 / CVE-2025-14300
    10.100.101.12   # Amcrest IP2M     → CVE-2020-5735 / CVE-2020-5736  (port 37777!)
    10.100.101.39   # Shelly Plug S    → CVE-2026-64823 HA XSS
    10.100.101.40   # Shelly2PM Gen4   → CVE-2026-64823 HA XSS
    10.100.101.41   # Tapo L530        → CVE-2023-38907 session replay
    10.100.101.34   # Tapo L530
    10.100.101.42   # Tapo L530
    10.100.101.43   # Tapo L530
    10.100.101.44   # Tapo L530
    10.100.101.45   # Tapo L530
    10.100.101.55   # Meross MSG100    → CVE-2021-35067 garage replay
    10.100.101.56   # Reolink D340W    → CVE-2025-55637 DDNS injection
  )
  for ip in "${cve_targets[@]}"; do
    do_ports "$ip"
    do_fingerprint "$ip"
  done

  # Remaining inventory hosts (ports + fingerprint — no vuln to save time)
  banner "STEP 3/5  Port + OS scan — remaining hosts"
  mapfile -t all_ips < <(scope_ips)
  for ip in "${all_ips[@]}"; do
    # skip CVE targets already done and the Panda-Pivot
    if [[ " ${cve_targets[*]} " != *" $ip "* ]] && [[ "$ip" != "$PIVOT_IP" ]]; then
      do_ports       "$ip"
      do_fingerprint "$ip"
    fi
  done

  # Vuln scan: CVE targets only (saves 2-3 h on non-interesting devices)
  banner "STEP 4/5  Vulnerability scan — CVE targets"
  for ip in "${cve_targets[@]}"; do
    do_vuln "$ip"
  done

  # Panda-Pivot: scan only (it's already compromised — document its exposed surface)
  banner "STEP 5/5  Panda-Pivot ($PIVOT_IP) — surface scan only"
  local pdir; pdir=$(new_run "$LABEL" "$PIVOT_IP")
  save_cmd "$pdir" "sudo nmap -sS -sV -O $T $PIVOT_IP -oA ${pdir}/pivot"
  echo "[i] Scanning pre-compromised pivot host to document exposed attack surface"
  sudo nmap -sS -sV -O $T "$PIVOT_IP" -oA "${pdir}/pivot" | tee "${pdir}/stdout.txt" || true
  end_run "$LABEL" "$PIVOT_IP"
  echo ">> evidence: $pdir"

  episode_stop "$ep_id"

  echo
  echo "╔══════════════════════════════════════════════════════════╗"
  echo "║  RECON SESSION COMPLETE                                  ║"
  echo "║  Evidence → runs/scan/                                   ║"
  echo "║  Next:  ./03_web/web.sh survey <ip>                     ║"
  echo "║         ./04_brute_force/brute.sh rtsp 10.100.101.10    ║"
  echo "╚══════════════════════════════════════════════════════════╝"
}

# ─────────────────────────────────────────────────────────────
cmd="${1:-}"; shift || true
case "$cmd" in
  session)       do_session ;;
  discovery)     do_discovery ;;
  masscan)       do_masscan ;;
  ports)         do_ports "$@" ;;
  fingerprint)   do_fingerprint "$@" ;;
  vuln)          do_vuln "$@" ;;
  all)           do_all "$@" ;;
  all-inventory) mapfile -t ips < <(scope_ips); do_all "${ips[@]}" ;;
  *) sed -n '2,22p' "$0"; exit 1 ;;
esac
