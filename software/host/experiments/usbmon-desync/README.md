# usbmon bisect for the `--filter-nak` framer desync (#25)

## Question

With `--filter-nak`, `ovctl.py sniff` loses framing sync
(`Unmatched byte NN - discarding`, eventually `assert r_addr == io_ext`). A
consumer that enables the same gateware filter but issues **no register I/O
during the capture window** (fvdpol's `ov_snapshot.py`, and `mincapture.py`
here) runs loss-free for billions of packets.

Is the corruption introduced **on the board** (FPGA ↔ FT2232H, or the FT2232H's
USB side) or **in host software** (LibOV's multi-threaded byte assembly)?

## Method

`OVDevice.__comms` (LibOV.py) frames the FTDI byte stream on a dedicated thread.
`ovctl.py sniff`'s status loop reads CSRs ~1×/s with a *synchronous*
`libusb_bulk_transfer` from the **main** thread, on the **same libusb context**
the `__comms` thread is pumping with `libusb_handle_events`. Two threads driving
one context can reap IN-stream transfer completions out of submission order.

usbmon logs URB completions in the kernel's completion order, before libusb
userspace touches them. So:

1. Capture all USB traffic for the OpenVizsla with usbmon while a client runs
   with `--filter-nak`.
2. Reframe the captured bytes offline, concatenated **in capture order**, with
   the exact same outer service framing LibOV uses (`reframe.py`).
3. Compare with the client's own live framing result.

| observation | conclusion |
|---|---|
| client desyncs, offline reframe is **CLEAN** | host software — LibOV's concurrent assembly reorders a ~4 KB block; the bytes on the wire are fine |
| client desyncs, offline reframe **also DESYNCs** | upstream of the host — FPGA ↔ FT2232H or the FT2232H's USB side (→ logic-analyzer / SSN territory) |
| client clean, reframe clean | baseline check (run `mincapture` first) |

`reframe.py` mirrors `LibOV.py` (service magics / sizes) and `fastftdi.c`
(2-byte FT2232H status header stripped per 512-byte USB packet). It walks **two**
layers, matching LibOV's structure:

- **outer** — the `0x55/0xAA/0xA0../0xD0/0xE0` service stream (LibOV `__comms`)
- **inner** — the concatenated `0xD0` payloads walked as pure rxcsniff records
  (LibOV `SDRAMReadService` feeds these to `rxcsniff` alone). LibOV's
  `Unmatched byte` prints are mostly from this inner framer.

For each layer it reports CLEAN, `DESYNC (RECOVERED)` — slipped once then
re-locked on a later header — or `DESYNC (NEVER RECOVERED)`. A dense stream is
expected to self-heal; a sparse `--filter-nak` stream (mostly `0x00`, no resync
marker) is not. If both layers are CLEAN / RECOVERED while the live client
desynced, the fault is in LibOV's consumption, not on the wire.

## Prerequisites

- **Current `master` gateware.** Earlier builds miss the SSN/SSO drive-strength
  reductions, so a board-side conclusion drawn against old gateware is suspect.
  The vendor-bundled `software/host/ov3.fwpkg` is a 2024 build — do **not** run
  the experiment against it. Build a fresh one on the ISE host
  (`cd ~/xilinx-ise_14.7 && ./run.sh make`, output
  `software/fpga/ov3/build/ov3/ov3.fwpkg`) and either copy it over
  `software/host/ov3.fwpkg` or point `OV_PKG` / `ovctl.py --pkg` at it. Load it
  once with `ovctl.py --pkg <fwpkg> -l` (the run scripts then reuse whatever is
  on the FPGA). `run_bisect.sh` echoes the bitstream timestamp it sees — record
  it with every result.
- Root (usbmon), `tcpdump`.
- A configured OpenVizsla with a NAK-heavy High-Speed DUT (makes the effect
  obvious within seconds for the `ovctl` case). The V3 enumerates as
  `1d50:607c` once its EEPROM is programmed; `run_bisect.sh` defaults to that,
  override with `OV_VIDPID=vvvv:pppp`.

## Run

```sh
# clean reference: enable the filter, no register I/O for 20 s
sudo ./run_bisect.sh mincapture 20

# the failing case: ovctl.py sniff, CSR status loop active
sudo ./run_bisect.sh ovctl 20
```

Each run writes `results/<mode>-<ts>.{pcap,client.log,verdict.txt}` and prints
both verdicts. To reframe an existing capture:

```sh
./reframe.py results/ovctl-<ts>.pcap
./reframe.py some.pcap --bus 3 --dev 7 --dump-stream stream.bin
```

`./selftest.py` synthesizes a usbmon pcap from a known frame stream and checks
that `reframe.py` reconstructs it and flags a deliberate 1-byte deletion — no
hardware, run it to sanity-check the reframer on any machine.

## Tracking runs across scenarios and batches

With several gateware builds and several sniff settings under test at once,
every invocation of `run_bisect.sh` is tagged with a **scenario** — built from
`GATEWARE_TAG` (required — a short name like `master`, `bundled`, or
`tmon-filternak`), whether the sniff reloaded the bitstream (`NO_LOAD`), and
the filter flags (`FILTER_NAK`/`FILTER_SOF`) — and appends one line to
`results/manifest.jsonl` recording the scenario, the client's live desync
result, and the offline reframe verdict for both layers. The manifest is
**append-only**: it is never rewritten, so re-running the same scenario later
(a different day, to widen a thin sample) just adds more rows to it — nothing
needs to be merged by hand. Tag a set of runs with `BATCH=<label>` if you want
to be able to filter to just that run later; it's metadata only, aggregation
is per-scenario by default and spans every batch.

```sh
GATEWARE_TAG=master   OV_PKG=~/ov_ftdi/software/host/ov3.fwpkg \
    BATCH=20260905-tomasz-recheck sudo -E ./run_bisect.sh ovctl 60
GATEWARE_TAG=master NO_LOAD=1 BATCH=20260905-tomasz-recheck sudo -E ./run_bisect.sh ovctl 60

./aggregate.py                              # every scenario, every batch so far
./aggregate.py --scenario master_reload_nak1_sof0
./aggregate.py --batch 20260905-tomasz-recheck
./aggregate.py --list-batches
```

`aggregate.py` reports N / desync count / rate per scenario, plus a count of
runs where the *wire* (not just the live client) desynced — those are worth a
second look since they're a stronger claim than the usual self-healing blip.
`--dump-blips results/blips` (on by default in `run_bisect.sh`) writes one
context file per desync event — the preceding parsed-frame sequence plus hex
around the offset — for looking at whether a packet pattern precedes it.

## Notes

- `mincapture.py` is a ~90-line stand-in for `ov_snapshot.py`: open device,
  drop LibOV's verbose per-packet printer (`rxcsniff.service.handlers = []`),
  enable SDRAM ring + `CSTREAM_CFG` bit 0 (stream) + bit 2 (NAK filter), sleep,
  tear down. No status loop. Keeping the verbose printer makes the consumer slow
  enough to starve the framing thread on its own -- both clients here run quiet
  (`ovctl` via `--format custom`) so the only variable is the CSR status loop.
- usbmon timestamps every URB, so if out-of-order **completion** is the
  mechanism it should also be visible directly in the pcap (compare URB `id`
  submission vs completion order in Wireshark).
- Capture the whole `usbmonN` bus; `reframe.py` filters to the OpenVizsla by
  picking the busiest bulk-IN device (override with `--bus`/`--dev`).
- If `tcpdump` warns about a snap length, re-run with `-s 0` (the script already
  passes it).
