# Issue #25 — capture-engine init probe

Instrumentation added to `software/host/ovctl.py` to settle one question:
**does the SDRAM ring-pointer reset actually take effect at session start?**

## Why

The RTL resets both pointers to `ring_base` on the rising edge of `go`
(`ovhw/sdram_sink.py:142-146`, `ovhw/sdram_host_read.py:143-147`), and
`ovctl.py` creates that edge (low, set base/end, high). Both halves read
correctly. But capture is not enabled until `CSTREAM_CFG` is written, roughly
60 lines later — so if the reset works, then between the GO edges and the
capture enable the sink has nothing to write, `wptr` stays at base, `rptr` is
set to base too, `blocked` holds, and **the board cannot send anything at all**.

The ramp measurement says it does send something: ~48 s old data. One of those
statements is wrong, and the probe reads the registers rather than arguing.

## Switches

All opt-in. With none set, `do_sniff` behaves exactly as before.

| variable | effect |
|---|---|
| `OV25_PROBE=1` | dump engine state at each step of SDRAM init |
| `OV25_PRECAPTURE_DELAY=2.0` | wait N s between the GO edges and `CSTREAM_CFG`, counting bytes the board sends |
| `OV25_CLEAR_CSTREAM=1` | write `CSTREAM_CFG=0` before the GO edges |
| `OV25_PROBE_OUT=<path>` | append probe output here instead of stderr |

Each dump line is `[ov25] <tag> wptr=… rptr=… go=<sink>/<host_read> cfg=…
base=<sink>/<hr> end=<sink>/<hr> wrap=… rx=<bytes received so far>`, and a
`[ov25-json]` line with the full row list is emitted just before capture is
enabled. **Pointers are 16-bit word addresses** — double them for bytes.

## Experiments

Run each both ways on the *previous* session's exit, because that is what the
hypothesis turns on: a clean exit runs the teardown at `ovctl.py:397-402`
(both GO bits and `CSTREAM_CFG` cleared, Ctrl-C included), a `SIGKILL` does not.

### E1 — the binary one, run this first

```sh
OV25_PRECAPTURE_DELAY=2 ovctl.py sniff hs --filter-nak --out run.pcap
```

Capture is disabled for those two seconds. **Any non-zero `rx=` before the
`after CFG=…` line proves the board is emitting data that is not from this
session.** No register interpretation needed. One line of output decides it.

### E2 — where in the sequence it breaks

```sh
OV25_PROBE=1 OV25_PRECAPTURE_DELAY=2 ovctl.py sniff hs --filter-nak --out run.pcap
```

Read down the dump lines:

- `on entry` — what the previous session left. Note `cfg`: if bit 0 is set,
  the producer is still enabled from last time.
- `after GO=0` / `after RING_BASE` — did those writes land at all
  (`CSRStorage` is host-readable, so these read back what was written).
- **`after GO=1`** — the one that matters. A working reset shows
  `wptr=00000000 rptr=00000000`. Anything else is the previous session's state
  surviving the edge.
- `pre-capture` ×N — with capture still off they must both stay at 0.

### E3 — does clearing the producer enable change anything

```sh
OV25_PROBE=1 OV25_CLEAR_CSTREAM=1 OV25_PRECAPTURE_DELAY=2 \
    ovctl.py sniff hs --filter-nak --out run.pcap
```

`do_sniff` never clears `CSTREAM_CFG` at init. If a previous client was killed
it stays enabled, and since `HF0_FIRST` is stuffed on the *rising* edge of
`ena` = `CSTREAM_CFG` bit 0 (`ovhw/whacker/whacker.py:37`,
`ovhw/whacker/producer.py:69-71`), a session that inherits a running producer
never gets a start marker. That matches `HF0_FIRST` being absent in exactly the
runs that desync — so this run tests whether an explicit clear restores it.

Run E2 before E3. If both the clear and the probe land in the same run and the
desync disappears, we will not know which change did it, and we will have no
`on entry` data to show upstream.

## Recording

Note for each run: the gateware build, whether the FPGA was reloaded (`-l`),
and **how the previous client exited** (clean / Ctrl-C / SIGKILL). That last
column is the discriminator the whole hypothesis rests on and is not otherwise
recoverable from the capture.
