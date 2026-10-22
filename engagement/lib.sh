#!/usr/bin/env bash
# Shared helpers for the engagement scripts: scope guard, run folders, HA-style markers.
# Lives at the engagement root; each phase script sources it as:  . "$(dirname "$0")/../lib.sh"

set -euo pipefail

# --- paths -------------------------------------------------------------------
ENG_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# RUNS_DIR can be overridden via env var so evidence can live on a local writable
# path when the engagement root is a read-only network mount (e.g. CIFS from Windows).
# Default: <engagement_root>/runs
# Override: export RUNS_DIR=~/engagement-runs   (then source lib.sh)
RUNS_DIR="${RUNS_DIR:-${ENG_ROOT}/runs}"
MARKERS="${RUNS_DIR}/markers.log"
TARGETS_CSV="${ENG_ROOT}/00_scope/targets.csv"
TARGETS_TXT="${ENG_ROOT}/00_scope/targets.txt"   # professor's format: one IP per line, # comments

# --- scope -------------------------------------------------------------------
# Only addresses in the target subnet are ever allowed to be touched.
SCOPE_CIDR_PREFIX="10.100.101."   # tunnel-side target subnet
GATEWAY="10.100.101.1"            # path/infra: reachability check only, never a target

in_scope() {
  local ip="$1"
  [[ "$ip" == ${SCOPE_CIDR_PREFIX}* ]] || return 1
  [[ "$ip" != "$GATEWAY" ]] || return 1          # gateway is infra, out of scope as a target
  return 0
}

require_scope() {
  local ip
  for ip in "$@"; do
    if ! in_scope "$ip"; then
      echo "[SCOPE VIOLATION] refusing to target '$ip' (must be ${SCOPE_CIDR_PREFIX}0/24, not the gateway)" >&2
      exit 2
    fi
  done
}

# --- run bookkeeping ---------------------------------------------------------
ts()      { date -u +%Y-%m-%dT%H:%M:%SZ; }
tsfile()  { date -u +%Y%m%d-%H%M%SZ; }

# new_run <label> <target> -> echoes the run folder path (only), writes START marker
# IMPORTANT: marker line goes to stderr so callers using dir=$(new_run ...) capture
# only the path, not the marker text.
new_run() {
  local label="$1" target="${2:-all}"
  local dir="${RUNS_DIR}/${label}/$(tsfile)_${target//[^0-9A-Za-z._-]/_}"
  mkdir -p "$dir"
  mkdir -p "$(dirname "$MARKERS")"
  echo "START ${label} ${target} $(ts)" | tee -a "$MARKERS" >&2
  echo "$dir"
}

# end_run <label> <target>
end_run() {
  local label="$1" target="${2:-all}"
  echo "STOP  ${label} ${target} $(ts)" | tee -a "$MARKERS"
}

# save_cmd <run_dir> <command string>  -> records the exact command for reproducibility
save_cmd() { echo "$2" > "$1/cmd.txt"; }

# live targets — reads targets.txt (professor format) when present, else falls back to targets.csv
# Strips comment lines and inline comments; skips the Panda-Pivot (.4) which is a foothold host.
scope_ips() {
  if [[ -f "$TARGETS_TXT" ]]; then
    awk 'NF && $1 !~ /^#/ {print $1}' "$TARGETS_TXT" | grep -v '^10\.100\.101\.4$'
  else
    tail -n +2 "$TARGETS_CSV" | cut -d, -f3
  fi
}

# Raw IP list including the Panda-Pivot foothold (for lateral movement phase only)
scope_ips_all() {
  if [[ -f "$TARGETS_TXT" ]]; then
    awk 'NF && $1 !~ /^#/ {print $1}' "$TARGETS_TXT"
  else
    tail -n +2 "$TARGETS_CSV" | cut -d, -f3
  fi
}

# Write a temp file of IPs for tools that need -iL (masscan)
targets_file() {
  local tmp; tmp=$(mktemp)
  scope_ips > "$tmp"
  echo "$tmp"
}

# --- episodes (dataset grouping) --------------------------------------------
# An episode brackets one campaign so assemble.py can group its steps into a trajectory.
# Usage:  episode_start <id>   ...run actions...   episode_stop <id>
episode_start() {
  local id="${1:-ep_$(tsfile)}"
  mkdir -p "$(dirname "$MARKERS")"
  echo "START EPISODE ${id} $(ts)" | tee -a "$MARKERS"
  echo "$id" > "${RUNS_DIR}/CURRENT_EPISODE"
}
episode_stop() {
  local id="${1:-$(cat "${RUNS_DIR}/CURRENT_EPISODE" 2>/dev/null || echo unknown)}"
  echo "STOP  EPISODE ${id} $(ts)" | tee -a "$MARKERS"
  rm -f "${RUNS_DIR}/CURRENT_EPISODE"
}
