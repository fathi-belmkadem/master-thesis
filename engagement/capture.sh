#!/usr/bin/env bash
# Optional network capture for the dataset: tcpdump on the WireGuard tunnel, bracketed to an episode.
# The pcap lets the same campaigns double as a labeled network-IDS dataset and feeds environment
# feedback to the agent later. Run it alongside an episode:
#
#   ./capture.sh start <episode_id>     # begins tcpdump on the tunnel -> runs/pcap/<episode>.pcap
#   ...  . lib.sh; episode_start <id>;  run actions;  episode_stop <id>  ...
#   ./capture.sh stop  <episode_id>
#
. "$(dirname "$0")/lib.sh"

IFACE="${WG_IFACE:-fordaysec}"      # capture on the tunnel interface
PCAP_DIR="${RUNS_DIR}/pcap"
PIDF() { echo "${PCAP_DIR}/$1.pid"; }

start() {
  local id="${1:?episode id required}"; mkdir -p "$PCAP_DIR"
  command -v tcpdump >/dev/null || { echo "[!] tcpdump missing"; exit 3; }
  local pcap="${PCAP_DIR}/${id}.pcap"
  # capture only tunnel-side target-subnet traffic; scope enforced by the filter
  sudo tcpdump -i "$IFACE" -w "$pcap" -U "net ${SCOPE_CIDR_PREFIX}0/24" >/dev/null 2>&1 &
  echo $! | sudo tee "$(PIDF "$id")" >/dev/null
  echo "[ok] capturing ${IFACE} -> ${pcap} (pid $(cat "$(PIDF "$id")"))"
}

stop() {
  local id="${1:?episode id required}"; local pidf; pidf="$(PIDF "$id")"
  [[ -f "$pidf" ]] || { echo "[!] no capture pid for '$id'"; exit 1; }
  sudo kill "$(cat "$pidf")" 2>/dev/null || true
  sudo rm -f "$pidf"
  echo "[ok] stopped capture for ${id}: ${PCAP_DIR}/${id}.pcap"
}

case "${1:-}" in
  start) shift; start "$@" ;;
  stop)  shift; stop "$@" ;;
  *) sed -n '2,12p' "$0"; exit 1 ;;
esac
