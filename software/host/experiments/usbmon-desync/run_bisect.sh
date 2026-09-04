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
#
# --- run tracking ---------------------------------------------------------
# Every run is tagged with a SCENARIO (what's under test) and appends one
# line to results/manifest.jsonl (never overwritten -- re-running the same
# scenario later just adds more samples to it). GATEWARE_TAG is required so
# scenario names stay stable and human-readable; see aggregate.py to sum
# manifest.jsonl into per-scenario hit rates across every batch so far.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOST="$(cd "$HERE/../.." && pwd)"
OUT="$HERE/results"
mkdir -p "$OUT"

MODE="${1:-mincapture}"
SECS="${2:-20}"
TS="$(date +%Y%m%dT%H%M%SZ)"
TAG="$OUT/${MODE}-${TS}"

GATEWARE_TAG="${GATEWARE_TAG:-untagged}"
BATCH="${BATCH:-}"
if [ "$GATEWARE_TAG" = untagged ]; then
  echo "WARNING: GATEWARE_TAG not set -- manifest entry will be scenario" \
       "'untagged_...'. Set GATEWARE_TAG=bundled|master|tmon-filternak (or" \
       "whatever) so runs group correctly in aggregate.py." >&2
fi
RELOAD_TAG="reload"; [ "${NO_LOAD:-0}" = 1 ] && RELOAD_TAG="noload"
# MODE is part of the scenario key: mincapture (no CSR I/O) is the clean
# reference and is expected to stay desync-free, so it must never share a
# scenario bucket with ovctl (CSR poll on, the actual #25 repro) -- mixing
# them would silently dilute the ovctl desync rate.
SCENARIO="${MODE}_${GATEWARE_TAG}_${RELOAD_TAG}_nak${FILTER_NAK:-1}_sof${FILTER_SOF:-0}"
echo "scenario: $SCENARIO  (batch: ${BATCH:-<none>})"

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

# --- (re)configure the FPGA so every run is self-contained --------------
# Reloading also wipes the SDRAM ring, so a run never starts against a dirty
# buffer left by a killed predecessor. Skip with NO_LOAD=1 to test whatever
# bitstream is already on the board.
if [ "${NO_LOAD:-0}" != 1 ]; then
  echo "loading gateware (${OV_PKG:-bundled ov3.fwpkg}) ..."
  python3 "$HOST/ovctl.py" ${OV_PKG:+--pkg "$OV_PKG"} -l -C \
      2>&1 | tee "${TAG}.load.log" | grep -E "Bitstream timestamp|error|Error" || true
fi

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
# Keep only the lines that matter (desync, crash, bitstream id, PERR) so the
# log stays small even when --format verbose dumps hundreds of MB of decode.
KEEP='Unmatched byte [0-9a-fA-F]+ - discarding|assert r_addr|AssertionError|ProtocolError|Traceback|Error|Bitstream timestamp|^PERR'
OVCTL_FORMAT="${OVCTL_FORMAT:-custom}"    # custom = quiet; verbose = the original #25 repro
FILTER_NAK="${FILTER_NAK:-1}"            # 1 = --filter-nak (default); 0 = off
FILTER_SOF="${FILTER_SOF:-0}"           # 1 = --filter-sof: drops SOF only, keeps the
#   NAK storm -> DENSE stream. Use FILTER_NAK=0 FILTER_SOF=1 to test whether a dense
#   stream self-heals a bad start where the sparse --filter-nak stream does not.
nak_args=()
[ "$FILTER_NAK" = 1 ] && nak_args+=(--filter-nak)
[ "$FILTER_SOF" = 1 ] && nak_args+=(--filter-sof)
echo "client: $MODE  (${SECS}s, filter_nak=$FILTER_NAK filter_sof=$FILTER_SOF, format=$OVCTL_FORMAT, no_load=${NO_LOAD:-0})"
set +e
case "$MODE" in
  mincapture)
    # quiet consumer, no register I/O in the window
    FILTER_NAK="$FILTER_NAK" python3 "$HERE/mincapture.py" "$SECS" 2>&1 \
        | grep -aE "$KEEP" > "${TAG}.client.log"
    CLIENT_RC=${PIPESTATUS[0]}
    ;;
  ovctl)
    # ovctl's ~1 Hz CSR status loop is the variable under test. --format custom
    # keeps it quiet (only the status loop differs from mincapture); --format
    # verbose reproduces the exact condition #25 was reported under.
    fmt_args=(--format "$OVCTL_FORMAT")
    [ "$OVCTL_FORMAT" != verbose ] && fmt_args+=(--out "${TAG}.ovctl.bin")
    timeout "$((SECS + 8))" python3 "$HOST/ovctl.py" sniff hs "${nak_args[@]}" \
        "${fmt_args[@]}" --timeout "$SECS" 2>&1 \
        | grep -aE "$KEEP" > "${TAG}.client.log"
    CLIENT_RC=${PIPESTATUS[0]}
    ;;
  *)
    echo "unknown mode '$MODE' (use: mincapture | ovctl)"; exit 2 ;;
esac
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
BITS="$(grep -m1 'Bitstream timestamp' "${TAG}.load.log" "${TAG}.client.log" 2>/dev/null | head -1 || true)"
if [ -n "$BITS" ]; then
  echo "gateware: ${BITS#*Bitstream }"
else
  echo "gateware: unknown (NO_LOAD set and no reconfigure this run)"
fi

echo
echo "=== client-side (LibOV live framing) ==="
# match LibOV's exact message, not our own summary line that quotes the phrase
UM_RE='Unmatched byte [0-9a-fA-F]+ - discarding'
CLIENT_UM=$(grep -cE "$UM_RE" "${TAG}.client.log" || true)
CLIENT_ASSERT=$(grep -cE "assert r_addr|AssertionError|ProtocolError" "${TAG}.client.log" || true)
echo "client rc            : $CLIENT_RC"
echo "'Unmatched byte' lines: $CLIENT_UM"
echo "assert/protocol errors: $CLIENT_ASSERT"
[ "$CLIENT_UM" != 0 ] && grep -m3 -E "$UM_RE" "${TAG}.client.log" | sed 's/^/  /' || true

echo
echo "=== usbmon reframe (offline, kernel completion order) ==="
python3 "$HERE/reframe.py" "${TAG}.pcap" --dump-blips "$OUT/blips" \
    --json-summary "${TAG}.reframe.json" \
    | tee "${TAG}.verdict.txt"

echo
echo "artifacts: ${TAG}.{pcap,client.log,verdict.txt}"

# --- manifest -----------------------------------------------------------
# One JSON line per run, appended -- never rewritten -- so this is safe to
# call across many separate batches/sessions and just accumulates. This is
# the source of truth for aggregate.py, independent of any per-run text log.
# Fields passed as argv (not interpolated into the script) since $BITS is
# free-text device output and could otherwise break the heredoc.
python3 "$HERE/record_run.py" \
    --manifest "$OUT/manifest.jsonl" \
    --ts "$TS" --scenario "$SCENARIO" --batch "$BATCH" \
    --gateware-tag "$GATEWARE_TAG" --gateware-bitstream "$BITS" \
    --reload "$RELOAD_TAG" --filter-nak "${FILTER_NAK:-1}" \
    --filter-sof "${FILTER_SOF:-0}" --mode "$MODE" --secs "$SECS" --tag "$TAG" \
    --client-rc "$CLIENT_RC" --client-unmatched "$CLIENT_UM" \
    --client-assert "$CLIENT_ASSERT" --reframe-json "${TAG}.reframe.json"
