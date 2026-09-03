#!/usr/bin/env bash
#
# Bisect the --filter-nak framer desync (OpenVizslaTNG/ov_ftdi#25): capture the
# OpenVizsla's USB traffic with usbmon while a client runs with --filter-nak,
# then reframe the captured bytes offline and compare with the client's own
# framing result.
#
#   sudo ./run_bisect.sh mincapture [seconds]     # clean reference client
#   sudo ./run_bisect.sh ovctl      [seconds]     # ovctl.py sniff (CSR poll on)
#
# Needs root (usbmon), tcpdump, and a configured OpenVizsla on the bus.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOST="$(cd "$HERE/../.." && pwd)"
OUT="$HERE/results"
mkdir -p "$OUT"

MODE="${1:-mincapture}"
SECS="${2:-20}"
TS="$(date +%Y%m%dT%H%M%SZ)"
TAG="$OUT/${MODE}-${TS}"

VIDPID="${OV_VIDPID:-0403:6010}"          # FT2232H; override if your board differs

# --- locate the device and its usbmon bus ---------------------------------
modprobe usbmon 2>/dev/null || true
line="$(lsusb -d "$VIDPID" | head -n1 || true)"
[ -n "$line" ] || { echo "no USB device $VIDPID found (lsusb -d $VIDPID)"; exit 1; }
BUS=$(echo "$line" | sed -E 's/Bus 0*([0-9]+) Device .*/\1/')
DEV=$(echo "$line" | sed -E 's/.*Device 0*([0-9]+):.*/\1/')
echo "device $VIDPID on bus $BUS device $DEV -> usbmon${BUS}"

# --- start the capture ---------------------------------------------------
echo "tcpdump -> ${TAG}.pcap"
tcpdump -i "usbmon${BUS}" -s 0 -w "${TAG}.pcap" -U 2>"${TAG}.tcpdump.log" &
TCPDUMP_PID=$!
trap 'kill $TCPDUMP_PID 2>/dev/null || true' EXIT
sleep 1                                   # let tcpdump attach

# --- run the client ----------------------------------------------------
echo "client: $MODE  (${SECS}s, --filter-nak)"
set +e
case "$MODE" in
  mincapture)
    python3 "$HERE/mincapture.py" "$SECS"        >"${TAG}.client.log" 2>&1
    ;;
  ovctl)
    timeout "$((SECS + 5))" python3 "$HOST/ovctl.py" sniff hs --filter-nak \
        --timeout "$SECS"                        >"${TAG}.client.log" 2>&1
    ;;
  *)
    echo "unknown mode '$MODE' (use: mincapture | ovctl)"; exit 2 ;;
esac
CLIENT_RC=$?
set -e

sleep 1
kill $TCPDUMP_PID 2>/dev/null || true
wait $TCPDUMP_PID 2>/dev/null || true
trap - EXIT

# --- verdicts --------------------------------------------------------
echo
echo "=== client-side (LibOV live framing) ==="
CLIENT_UM=$(grep -c "Unmatched byte" "${TAG}.client.log" || true)
CLIENT_ASSERT=$(grep -cE "assert r_addr|AssertionError|ProtocolError" "${TAG}.client.log" || true)
echo "client rc            : $CLIENT_RC"
echo "'Unmatched byte' lines: $CLIENT_UM"
echo "assert/protocol errors: $CLIENT_ASSERT"
[ "$CLIENT_UM" != 0 ] && grep -m3 "Unmatched byte" "${TAG}.client.log" | sed 's/^/  /' || true

echo
echo "=== usbmon reframe (offline, kernel completion order) ==="
python3 "$HERE/reframe.py" "${TAG}.pcap" | tee "${TAG}.verdict.txt"

echo
echo "artifacts: ${TAG}.{pcap,client.log,verdict.txt}"
