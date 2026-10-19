#!/usr/bin/env bash
# Phase 4 — Web attacks (session label: web)
# Fingerprint and probe the web interfaces found during recon (camera/plug/sensor UIs).
# Scope-guarded, marker-bracketed, evidence under runs/web/.
#
# Usage (from the engagement root):
#   ./03_web/web.sh fp     <ip> [port] [scheme]      # whatweb fingerprint (default 80 http)
#   ./03_web/web.sh nikto  <ip> [port] [scheme]      # nikto misconfig/known-file scan
#   ./03_web/web.sh sqlmap <url> [extra sqlmap args] # SQLi probe of a specific parameterised URL
#   ./03_web/web.sh survey <ip>                      # fp + nikto on 80(http) and 443(https)
#
# ATT&CK: T1190 (exploit public-facing app), T1059 (cmd injection), T1505.003 (web shell / installation)
. "$(dirname "$0")/../lib.sh"

LABEL=web

need() { command -v "$1" >/dev/null 2>&1 || { echo "[!] missing tool: $1 (see 01_setup)"; exit 3; }; }

do_fp() {
  local ip="$1" port="${2:-80}" scheme="${3:-http}"; require_scope "$ip"; need whatweb
  local dir; dir=$(new_run "$LABEL" "$ip")
  local cmd="whatweb -a3 -v ${scheme}://${ip}:${port}/"
  save_cmd "$dir" "$cmd"; echo "+ $cmd"
  eval "$cmd" | tee "$dir/whatweb.txt"
  end_run "$LABEL" "$ip"; echo ">> evidence: $dir"
}

do_nikto() {
  local ip="$1" port="${2:-80}" scheme="${3:-http}"; require_scope "$ip"; need nikto
  local dir; dir=$(new_run "$LABEL" "$ip")
  local cmd="nikto -host ${scheme}://${ip}:${port}/ -maxtime 600s -Tuning 123b -o ${dir}/nikto.txt"
  save_cmd "$dir" "$cmd"; echo "+ $cmd"
  eval "$cmd" | tee "$dir/stdout.txt" || true   # nikto nonzero on findings; keep output
  end_run "$LABEL" "$ip"; echo ">> evidence: $dir"
}

do_sqlmap() {
  local url="$1"; shift || true; need sqlmap
  local ip; ip=$(echo "$url" | sed -E 's#^[a-z]+://([^/:]+).*#\1#'); require_scope "$ip"
  local dir; dir=$(new_run "$LABEL" "$ip")
  # --batch: non-interactive; low risk/level by default so we don't hammer fragile devices
  local cmd="sqlmap -u \"$url\" --batch --risk=1 --level=2 --output-dir=${dir}/sqlmap $*"
  save_cmd "$dir" "$cmd"; echo "+ $cmd"
  eval "$cmd" | tee "$dir/stdout.txt" || true
  end_run "$LABEL" "$ip"; echo ">> evidence: $dir"
}

do_survey() {
  local ip="$1"
  do_fp "$ip" 80 http;  do_nikto "$ip" 80 http
  do_fp "$ip" 443 https; do_nikto "$ip" 443 https
}

cmd="${1:-}"; shift || true
case "$cmd" in
  fp)     do_fp "$@" ;;
  nikto)  do_nikto "$@" ;;
  sqlmap) do_sqlmap "$@" ;;
  survey) do_survey "$@" ;;
  *) sed -n '2,16p' "$0"; exit 1 ;;
esac
