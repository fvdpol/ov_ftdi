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
(2-byte FT2232H status header stripped per 512-byte USB packet). It is a
size-walk of the outer framing only — it does not verify inner checksums, which
is enough to detect a desync.

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
