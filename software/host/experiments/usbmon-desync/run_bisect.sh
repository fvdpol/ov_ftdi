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

# OpenVizsla V3 enumerates with its programmed EEPROM id, not the bare FT2232H
# 0403:6010. Override with OV_VIDPID if your board differs.
VIDPID="${OV_VIDPID:-1d50:607c}"

# --- locate the device and its usbmon bus ---------------------------------
modprobe usbmon 2>/dev/null || true
line="$(lsusb -d "$VIDPID" | head -n1 || true)"
if [ -z "$line" ]; then
  echo "no USB device $VIDPID found (lsusb -d $VIDPID)"
  echo "OpenVizsla V3 is 1d50:607c once its EEPROM is programmed; a bare"
  echo "FT2232H is 0403:6010. Set OV_VIDPID=vvvv:pppp to override. Seen now:"
  lsusb | sed 's/^/  /'
  exit 1
fi
BUS=$(echo "$line" | sed -E 's/Bus 0*([0-9]+) Device .*/\1/')
DEV=$(echo "$line" | sed -E 's/.*Device 0*([0-9]+):.*/\1/')
echo "device $VIDPID on bus $BUS device $DEV -> usbmon${BUS}"

# --- start the capture ---------------------------------------------------
if command -v tcpdump >/dev/null; then
  CAP=(tcpdump -i "usbmon${BUS}" -s 0 -U -w "${TAG}.pcap")
elif command -v dumpcap >/dev/null; then
  CAP=(dumpcap -i "usbmon${BUS}" -w "${TAG}.pcap")
else
  echo "need tcpdump (or dumpcap):  sudo apt install tcpdump" >&2
  exit 1
fi
echo "${CAP[*]}"
"${CAP[@]}" 2>"${TAG}.tcpdump.log" &
CAP_PID=$!
trap 'kill $CAP_PID 2>/dev/null || true' EXIT
sleep 2
if ! kill -0 $CAP_PID 2>/dev/null; then
  echo "capture process exited immediately:" >&2
  cat "${TAG}.tcpdump.log" >&2
  exit 1
fi

# --- run the client ----------------------------------------------------
echo "client: $MODE  (${SECS}s, --filter-nak)"
set +e
case "$MODE" in
  mincapture)
    # quiet consumer, no register I/O in the window
    python3 "$HERE/mincapture.py" "$SECS"        >"${TAG}.client.log" 2>&1
    ;;
  ovctl)
    # --format custom drops the verbose USBInterpreter printer, so the ONLY
    # difference from mincapture is ovctl's ~1 Hz CSR status loop.
    timeout "$((SECS + 5))" python3 "$HOST/ovctl.py" sniff hs --filter-nak \
        --format custom --out "${TAG}.ovctl.bin" \
        --timeout "$SECS"                        >"${TAG}.client.log" 2>&1
    ;;
  *)
    echo "unknown mode '$MODE' (use: mincapture | ovctl)"; exit 2 ;;
esac
CLIENT_RC=$?
set -e

sleep 1
kill $CAP_PID 2>/dev/null || true
wait $CAP_PID 2>/dev/null || true
trap - EXIT

if [ ! -s "${TAG}.pcap" ]; then
  echo "no pcap captured (${TAG}.pcap missing or empty)" >&2
  cat "${TAG}.tcpdump.log" >&2
  exit 1
fi

# --- verdicts --------------------------------------------------------
echo
BITS="$(grep -m1 'Bitstream timestamp' "${TAG}.client.log" || true)"
if [ -n "$BITS" ]; then
  echo "gateware: ${BITS#*Bitstream }"
else
  echo "gateware: FPGA not reconfigured this run -- check with: ovctl.py --pkg <fwpkg> -C"
fi

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
