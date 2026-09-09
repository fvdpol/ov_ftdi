# Register probe at session start -- 2026-09-09

Raw output from the opt-in `do_sniff` instrumentation added in `8f617cc`
(`OV25_PROBE=1 OV25_PRECAPTURE_DELAY=2`), plus the `HF0_FIRST` location in a
usbmon capture taken in parallel with each run.

Five `ovctl.py sniff hs --filter-nak --format pcap` sessions were run
back-to-back, nothing in between, with the Reloop Jockey 3 streaming a
continuous duplex load so the tapped wire stayed busy. `runN.probe.txt` is the
verbatim `[ov25]` dump for each; `hf0-marker-scan.txt` is the marker scan of the
matching usbmon capture.

`[ov25]` line fields: `wptr`/`rptr` = SDRAM ring pointers (16-bit word
addresses, atomic `SDRAM_SINK_PTR_READ` snapshot); `go` =
`SDRAM_SINK_GO`/`SDRAM_HOST_READ_GO`; `cfg` = `CSTREAM_CFG` (bit0 = producer
`ena`, bit2 = filter-NAK); `base`/`end` = ring base/end; `rx` = bytes the host
consumer has received since the probe hooked it (a plain byte count -- not a
live-vs-buffered indicator).

Steps: `on entry` (before any register write this session) -> `after GO=0` ->
`after RING_BASE` -> `after GO=1` (the pointer-reset edge) -> `pre-capture` xN
(2 s hold, capture still disabled) -> `after CFG=5` (capture enabled).

See the "Register probe at session start (2026-09-09)" section of
`../../FINDINGS.md` for what these show.

The pcaps themselves (sniff output + usbmon) are not committed -- kept out of
the tree like everything under `results/`.
