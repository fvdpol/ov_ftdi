# `--filter-nak` desync (#25) -- observations and hypotheses, 2026-09

Working notes for the ongoing investigation into OpenVizslaTNG/ov_ftdi#25. Kept in the
branch alongside the tooling it's built from -- update this as new evidence comes in rather
than letting it live only in a GitHub comment thread. See `README.md` for how the harness
itself works.

**How to read this document.** Every hypothesis here must be traceable to something checked
in data, code, or the gateware RTL -- not just a plausible-sounding story. Say explicitly
what's confirmed vs. still a guess, and what would distinguish them. We do not have the
whole picture (this is someone else's gateware, reverse-engineered from behavior and
partial RTL reading) and have already been wrong more than once on this investigation
specifically -- the original "start-of-stream" framing (withdrawn after Tomasz pointed out
the data showed mid-stream events), and a decode bug that made "0 HF0_FIRST/LAST everywhere"
look like a real finding when it was actually a bug hiding the marker on every zero-payload
record (see the Session markers section). Treat a clean, appealing narrative as reason for
suspicion, not confidence, until it's been checked against a case that should obviously
contradict it if the narrative were wrong.

## Confirmed results

- **Reload eliminates the desync; gateware doesn't matter.** 64-run matrix (N=8/cell,
  `--filter-nak`, 240s/run, batch `20260904-tomasz-recheck`): reload 0/24 desync across all
  3 gateware tested (bundled 2024, git master, Tomasz's `tmon-nordic/filter-nak`); no-load
  13/24 (bundled 4/8, master 4/8, tmon-filternak 5/8). Matches the original N=5 finding from
  Sep 3, now with real statistical weight.
- **Waiting for a proper drain at teardown appears to eliminate the no-load desync
  entirely.** `DRAIN_WAIT` experiment (batch `20260905-drain-wait`, master gateware, N=8):
  8/8 no-load runs clean when every session (including the one before it) waits for
  `HF0_LAST` before releasing the SDRAM path, vs. the established 4/8 (50%) no-drain
  baseline for the same condition. See the dedicated section below for the mechanism and
  caveats (N=8/one gateware so far, not yet independently replicated).
- **The desync is host-side framing, not wire corruption at the byte level** -- confirmed by
  usbmon capture: the outer `0xD0` service-stream layer reframes CLEAN in every single run
  so far, including every run where the inner (whacker/rxcsniff) layer or the live client
  desynced. The corruption specifically lives in the inner layer.
- **HF0_OVF (RX-path overflow) fires routinely even under `--filter-nak`+reload, with zero
  desync.** All 8 `bundled/reload` runs and all 8 `master/reload` runs showed nonzero
  in-band overflow (`inner_overflow_packets`): sums of 208,455 and 139,285 respectively
  across the 8 runs each, out of ~11M packets/run (~0.2%). So "no desync" != "no overflow" --
  worth stating plainly in any writeup, since it's easy to conflate the two.

## Overflow mechanism (why `--filter-nak` doesn't reduce it)

Traced `HF0_OVF`'s origin in the gateware: `ovf_insert.py`'s `OverflowInserter` sits
**upstream of the entire Whacker** (`producer -> filter_nak -> filter_sof -> consumer`, per
`whacker.py`'s wiring) and triggers purely on "the producer wasn't ready for the next ULPI
byte right now" -- nothing about `filter_nak` enters into that condition, since filtering
happens several stages later. So seeing overflow under `--filter-nak` isn't itself
surprising; it says nothing about whether the *rate* is normal or elevated.

Whether the overflow *count* itself is real (missed traffic) or inflated (spuriously
flagged) is checkable via the USB SOF frame number (an actual protocol sequence number,
increments every 125us, not filtered) either side of each `HF0_OVF` event -- a gap >1 means
a whole microframe of traffic is confirmed missing; 0 or 1 means no such evidence (not
proof nothing was lost -- SOF-gap granularity is whole-microframe, so a sub-microframe loss
wouldn't show). Built (`reframe.py`/`blip_classify.py`, per-event `overflow_sof_gap_gt1`)
but **not yet run at scale against real data** -- next step.

Also relevant: `ovctl`'s CSR-based overflow count (`OVF_INSERT_NUM_OVF`, read via a
register write + two reads) is itself subject to the same class of host-side register-I/O
confound #25 is about. The in-band `HF0_OVF` flag (decoded straight from wire bytes, zero
register I/O) is the more trustworthy of the two, same reasoning as why `mincapture.py`
(zero register I/O during the capture window) is the reference client.

**Open anomaly:** on the no-load cells, `client_overflow_events` (CSR) reads 0 for every
run where it was measured, while the in-band flag shows nonzero for 7-8/8 of the same
cells' runs. Both should read the same underlying hardware counter. Not yet root-caused.

## Session markers (HF0_FIRST/HF0_LAST) -- the strongest lead so far

The gateware inserts a "stuffed" marker packet on every `CSTREAM_CFG` stream-enable
0->1 edge (`HF0_FIRST`) and disable 1->0 edge (`HF0_LAST`) -- see `producer.py`:
`If(ena & ~en_last, packet_first.set(1))` and the mirror for `packet_last`. One pair per
capture *session*, regenerated every time, independent of reload. LibOV's own
`__RXCSniffService.consume()` gates ALL packet handling on having seen `HF0_FIRST`
(`got_start`), so this marker's presence/position is directly relevant to "is there stale
data from a prior session" (Tomasz's question, 2026-09-05: "In the corrupted stream, where
is the capture start marker?").

**Finding, 4 hand-checked samples (not yet run at scale):**

| run | condition | outcome | HF0_FIRST |
|---|---|---|---|
| `ovctl-20260904T112926Z` | reload | clean | present, packet #1 |
| `ovctl-20260904T163640Z` | no-load | clean | present, packet #1 |
| `ovctl-20260904T164128Z` | no-load | desync (bundled) | **absent entirely** |
| `ovctl-20260904T172104Z` | no-load | desync (master) | **absent entirely** |

The marker's presence tracks the **desync outcome**, not reload-vs-noload as a blanket
category -- a clean no-load run shows it exactly like a reload run does. This is a clean,
mechanistically coherent result: whatever fails at session start in the bad no-load cases
also swallows this marker, well before the framing itself visibly breaks deep into the
capture (14-16M bytes in, in the samples checked) -- reconciling Tomasz's objection to a
pure "start-of-stream" story (the visible break really is mid-stream) with a start-of-
session root cause (the earliest symptom is invisible unless you specifically look for it).

**A decode bug hid this finding initially** and is worth remembering: `decode_frame_packet()`
returned `None` for any record with zero USB payload bytes, before ever reading its flags
byte -- and the FIRST/LAST marker IS zero-payload by design (a synthetic marker, not a
captured packet). This silently hid every FIRST/LAST marker in the dataset until fixed
(`26560ef`). A second, related plumbing bug (`53150df`) meant even after that fix, a CLEAN
run's summary never carried the marker fields into the manifest (only the console print,
reading the raw per-capture stats directly, showed them) -- fixed by routing both the CLEAN
and desync verdict paths through one shared field set. Moral: verify a "both zero" result
against a case that should obviously be nonzero before trusting it.

**Not yet done:** running this check across all 64 main-matrix runs (needs
`sudo python3 reprocess.py` on alsa-test to backfill the fix onto already-captured pcaps --
no hardware re-run needed, `reprocess.py` re-walks stored pcaps).

## Why does no-load only *sometimes* fail? -- two candidate mechanisms

### (A) SDRAM ring pointer reset -- traced, does NOT explain it (ruled out as stated)

Hypothesis considered: HOST_READ's read pointer doesn't reset to a fresh position without a
full reload, so it starts reading stale/leftover ring content. **Checked directly against
the RTL and this is wrong as literally stated:** both `sdram_host_read.py`
(`If(go &~ gor, rptr.eq(ring_base))`) and `sdram_sink.py` (identical construct for `wptr`)
reset their respective pointers to `ring_base` on their own `GO` 0->1 edge -- reload or not.
The pointers themselves are not stale.

### (B) GO-write ordering race -- a hypothesis with a premise that isn't confirmed yet

`mincapture.py`'s (and `ovctl.py`'s) `setup()`/`do_sniff()` writes `SDRAM_SINK_GO` and then
`SDRAM_HOST_READ_GO` as **two separate, sequential USB control transfers**, not atomically.
The idea: if the whacker's stream-enable (`CSTREAM_CFG` bit 0, `ena`) is *already* active
when `SINK_GO`'s reset-to-`ring_base` edge fires (e.g. left on from an improperly-torn-down
previous session), the sink could immediately start writing live data from `ring_base`
forward, and if the gap before `HOST_READ_GO`'s own reset edge fires is long enough, the
sink could write and wrap the 16MB ring multiple times (at the observed ~6.6MB/s, one wrap
is ~2.4ms) before host-read's pointer resets -- host-read would then start consuming from
`ring_base` while the *live* write position is already several wraps ahead. For a reload,
the PHY needs to relock (HS chirp/handshake) after reconfiguration, so the same gap would
likely be quiet on the sink side -- masking the identical race by accident.

**This requires `ena` to already be active at the start of setup(), and that premise is NOT
confirmed -- checked `ovctl.py`'s `do_sniff` and it has a `finally: ... CSTREAM_CFG.wr(0)`
block, so on a *normal* exit (including its own internal `--timeout` firing, which is what
actually ends every run in our matrix -- the external `timeout` wrapper in `run_bisect.sh`
is only a safety net for a genuine hang) the stream should already be disabled before the
next session's setup() runs.** So as stated, this mechanism's precondition looks like it
shouldn't hold in the normal case -- caught this by re-reading `ovctl.py` before building
the experiment, not after, per the standing "back it with data/code, not a good story"
rule above. Two things could still make it real: (a) `CSTREAM_CFG`'s *register-write*
completing doesn't necessarily mean the *hardware* has fully settled to the disabled state
by the time the next session's writes land (a timing margin issue, not a code bug), or
(b) there's a narrower race window even with a working `finally` block that hasn't been
identified yet. **Before building the GO-reordering fix, the cheap, direct check is:** read
`CSTREAM_CFG`'s live value at the very start of a fresh no-load `setup()`, before writing
anything to it, across a number of no-load runs -- if it reads 0 every time as expected,
this hypothesis's premise fails and the reordering experiment isn't worth running as
currently framed. **Not yet done.**

## Drain-wait experiment -- DONE, positive result

Tests a different hypothesis than (A)/(B) above: incomplete draining at a session's
*teardown* leaves data behind (or the underlying SDRAM pipeline in a bad state) that
corrupts the *next* no-load session. `mincapture.py DRAIN_WAIT=1`: disables `CSTREAM_CFG`
first (the edge that stuffs `HF0_LAST`), then actively waits (2s default) for that marker
to actually arrive before disabling the SDRAM path -- the reverse of the default order,
which (bug found along the way, also fixed) disabled `SDRAM_SINK_GO`/`HOST_READ_GO`
*before* `CSTREAM_CFG`, shutting off the path that would carry `HF0_LAST` before the
marker even existed.

Sequencing (Frank): the drain only affects how session N leaves things for N+1, so the
test is 1 real, counted LOAD+DRAIN_WAIT priming run followed by N NOLOAD+DRAIN_WAIT runs
back-to-back (each depends on the previous run's drain, matching how the existing no-load
cells already run without a reload between iterations).

**Result (batch `20260905-drain-wait`, master gateware, N=8): 8/8 no-load+drain runs
clean** -- 0 desync, 0 wire-level corruption (`inner_blip`/`outer_bad`), vs. the
established no-drain baseline of 4/8 (50%) for the same gateware/condition. If the true
rate were still 50%, 8/8 clean by chance is ~0.4% likely -- this looks like a real effect,
not a fluke, though N=8 against one gateware is still a modest sample and worth expanding
(other gateware, larger N) before calling it fully settled.

**How this fits with (A)/(B) above:** `ovctl.py`'s `finally` block already sets
`CSTREAM_CFG=0` promptly on a normal exit, so the register itself isn't stuck enabled --
that's a different, weaker guarantee than confirming the underlying SDRAM sink pipeline
has actually finished draining in-flight data before the next session begins writing.
`DRAIN_WAIT` checks the latter (waits for the actual `HF0_LAST` marker to arrive) rather
than just the former (the register write completing). This is consistent with hypothesis
(B)'s specific mechanism (a live stream at the moment of the next session's `GO` writes)
being wrong as stated, while still landing on "something about session-to-session
transition state matters" as the real root cause -- just a different piece of it than
originally guessed.

## Ruled out

- **Long Mealy chain** (Tomasz's gateware timing concern, `producer.py`'s cfilt-to-Whacker
  combinational path): confirmed by Tomasz not relevant to this bug -- current builds
  achieve timing closure with slack to spare; the concern is forward-looking for his own
  upcoming feature work, not a source of glitches in the bitstream we're testing against.
- **Gateware version**: bundled 2024, git master (SSN/SSO drive-strength fixes), and
  Tomasz's `tmon-nordic/filter-nak` branch (block-RAM queues + the Mealy-chain reduction)
  all show the identical reload/no-load pattern. None of the gateware differences tested so
  far change the outcome.

## Open questions / next steps

1. **Expand the drain-wait result** (currently N=8, one gateware) -- more iterations,
   other gateware, before treating it as fully settled. This is the leading actionable
   result so far.
2. Port `DRAIN_WAIT` (or the equivalent teardown fix) into `ovctl.py` itself -- the actual
   client our main matrix and any eventual upstream fix would use, not just `mincapture.py`.
3. `sudo python3 reprocess.py` to backfill the FIRST/LAST marker fields across all 64
   main-matrix runs -- turn the 4 hand-checked samples into a systematic answer. The
   CSTREAM_CFG-at-setup-start diagnostic (hypothesis B) will also passively accumulate data
   on any future `mincapture.py` run now that it's built in -- check it opportunistically,
   no dedicated experiment needed unless drain-wait's result doesn't hold up under more N.
4. Run the SOF-gap real-vs-inflated check on the HF0_OVF events at scale (built, not yet
   applied broadly).
5. Resolve the `ovf_csr` vs `ovf_pcap` discrepancy on no-load cells.
6. Fold all of the above into the next #25 reply.
