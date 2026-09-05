# `--filter-nak` sniff desync (ov_ftdi #25) — findings to date

*Living draft, revised as data comes in. Last data refresh: run
`./gen_report_tables.py --update issue25-report.md` after new captures or a
reprocess. This is the externally-shareable summary; day-to-day working notes,
dead ends and internal hypotheses live in `FINDINGS.md`. The raw data behind the
numbers — the run manifest and a sample of per-event dumps — is in `evidence/`
(no pcaps; those are ~1 GB each and stay on the rig).*

## TL;DR

On a `--filter-nak` sniff, LibOV's framer loses sync partway into ~half of all
sessions that were started **without reconfiguring the FPGA first**. It is an
**initialisation problem, not a timing or gateware bug** — all three gateware
builds behave identically and timing closes with slack.

What happens: the OpenVizsla's SDRAM capture ring is **not emptied between
sessions**. When a new session starts, both ring pointers reset to `ring_base`
(per the RTL) on top of the *previous* session's leftover bytes. The client
reads that stale data out first, fast, until it catches up to where the current
session is actually writing. That catch-up point is a **seam** between two
unrelated stretches of capture — and it is the seam that LibOV's framer trips
on. After it re-locks, the rest of the session is fine.

This was **confirmed directly** by playing a known ramp signal into the DUT
throughout the capture (§3, "Confirmation"): across the seam the decoded ramp
jumps ~48 seconds *forward*, i.e. the bytes before the seam are ~48 s older than
the bytes after it — a previous session's data.

**Fixes, best to bluntest:** have the gateware guarantee an empty ring on
capture-enable; or have the client drain the ring at start (waiting for the
`HF0_LAST` marker at the previous teardown makes it 49/49 clean here); or
reconfigure the FPGA before every session (works, but re-inits the OV3's own
ULPI PHY on the sniffed bus — which has twice knocked this DUT off the bus at
sniff start with no auto-recovery, so it is not a free operation).

---

**Confidence note.** Everything here is backed by captured data, the OpenVizsla
gateware RTL, or LibOV source, and is flagged where it is still a hypothesis.
All captures use a **Reloop Jockey 3** as the sniffed device (DUT). It is a
High-Speed device whose driver keeps playback/capture URBs flowing continuously,
so the bus is steadily busy; under `--filter-nak` most of what survives the
filter is SOF plus the playback stream, whose payload here is low-entropy
(mostly zero). The DUT's traffic carries no timestamp or sequence field of its
own, so some of the fine detail below (packet types either side of the event,
the byte pattern at the trip point) may be specific to this DUT's data and not
general. We have already revised three conclusions in this investigation as
better data arrived — a "start-of-stream" framing the data later contradicted; a
decode bug that made a marker look absent everywhere; and a "byte-sync slip, no
data loss" reading that a wider analysis window overturned — so treat a tidy
story as a prompt to check it further.

---

## 1. Test objective and method

We are trying to pin down why LibOV's whacker/rxcsniff framer loses sync
("`Unmatched byte NN - discarding`") on some `--filter-nak` sniff sessions but
not others. Method: run the sniff client while capturing the OpenVizsla's *own*
USB traffic with `usbmon`/`tcpdump`, then reframe those kernel-ordered bytes
offline and compare against what the live client did. This separates "the bytes
on the wire from the OV3 were already wrong" from "the bytes were fine, the
client mis-consumed them." A minimal client (`mincapture.py`) that issues zero
register I/O during the capture window is used as a clean reference alongside
`ovctl.py sniff`. Each cell is repeated N times; the matrix varies the gateware
build, whether the FPGA was reconfigured before the run, and whether the
*previous* session drained cleanly.

---

## 2. Scenario results

Hit rate per (gateware × condition). Regenerated from `results/manifest.jsonl`:

<!-- BEGIN scenario-table -->
| gateware | condition | runs | desync | rate |
|---|---|--:|--:|--:|
| bundled | reload | 8 | 0 | 0% |
| master | reload | 8 | 0 | 0% |
| tmon-filternak | reload | 8 | 0 | 0% |
| bundled | no-load | 31 | 17 | 55% |
| master | no-load | 8 | 4 | 50% |
| tmon-filternak | no-load | 8 | 4 | 50% |
| bundled | no-load + drain-wait | 16 | 0 | 0% |
| master | no-load + drain-wait | 17 | 0 | 0% |
| tmon-filternak | no-load + drain-wait | 16 | 0 | 0% |
| bundled | reload + drain-wait | 1 | 0 | 0% |
| master | reload + drain-wait | 2 | 0 | 0% |
| tmon-filternak | reload + drain-wait | 1 | 0 | 0% |
| | | | | |
| **all** | **reload** | **24** | **0** | **0%** |
| **all** | **no-load** | **47** | **25** | **53%** |
| **all** | **no-load + drain-wait** | **49** | **0** | **0%** |
| **all** | **reload + drain-wait** | **4** | **0** | **0%** |
<!-- END scenario-table -->

*"reload" = FPGA reconfigured from the bitstream before the run. "no-load" = the
bitstream left as-is from the previous run. "drain-wait" = every session,
including the one before it, waited for the `HF0_LAST` marker before releasing
the SDRAM read/sink path at teardown, instead of disabling it immediately.
Gateware builds: `bundled` = the 2024 bitstream shipped in the fwpkg; `master` =
current git master; `tmon-filternak` = desowin's `tmon-nordic/filter-nak`
branch. The no-load `bundled` cell is larger because it pools several batches,
including the runs with the ramp signal playing (§3 "Confirmation") — that is
the same scenario, only the playback payload differs. Rows captured against a
disconnected DUT (near-zero reframed bytes) are dropped.*

### Observations

1. **The desync only occurs when the FPGA was not reconfigured before the run.**
   0/24 with reload, 25/47 (53%) without. Every reload cell is clean.
2. **Making the previous session drain cleanly eliminates it.** 0/49 no-load
   runs desync when the prior session waited for `HF0_LAST` before tearing down
   the SDRAM path, versus 25/47 (53%) without that wait. The priming
   reload+drain runs are counted in the table and are also clean.
3. **The three gateware builds behave the same.** Same ~50% no-load rate on
   each; reload and drain-wait clean on each. None of the gateware differences
   we tested changes the outcome.
4. **RX-path overflow (`HF0_OVF`) — presence alone doesn't discriminate, but
   *where* it lands does.** Overflow fires on clean reload runs too, so "saw
   overflow" vs "desynced" are not the same thing. But within a desync run the
   overflow events are all bunched at the very start of the stream and then stop
   (detailed in section 3) — which does line up with the onset mechanism. Aside: the
   in-band overflow-flag count and `ovctl`'s register-read overflow count
   disagree sharply on the no-load runs checked for it (nonzero in-band on
   22 of 24, zero via the register on all 24) — unexplained, noted for
   completeness.

### Discussion — no-load vs reload vs drain

Reload and "previous session drained" both fix the symptom, and the common
thread is the state the SDRAM capture path is left in between sessions. A
reconfigure clears that state wholesale; a clean drain empties it. Leaving it
alone is what fails.

**Reload is not a free reset, though.** Reconfiguring the FPGA re-initialises
the OV3's own ULPI PHY, which is electrically on the sniffed bus — on relock it
drives an HS chirp/handshake, i.e. a real transient on the D+/D- lines the host
and DUT share. This is not theoretical: on this rig we have **at least twice
seen the DUT drop off the bus at the exact moment a sniff was started, and not
recover on its own** (a manual power-cycle was needed). So "just reload every
time" is not a neutral init step — it can disturb, and has disturbed, the very
link being measured. Drain-wait, by contrast, touches only the SDRAM read/sink
path and leaves the PHY and the bus alone — a point in its favour as the
preferred fix, over mandating a reconfigure.

From an application's point of view this matters because **a sniff tool has no
control over how the previous tool left the device.** If a non-empty / not-fully
reset capture path can corrupt the next session's stream, then the cleanest fix
is for the gateware to guarantee an empty ring on capture-enable, or failing
that for the client to drain the path as part of *start*. A full reconfigure
works but is the blunt option. Relying on "the last user shut down tidily" is
not something a tool can depend on.

---

## 3. Deep-dive: the onset of the desync

The tables and per-event figures in this section come from **one batch of 12
no-load desync runs** (`bundled`/`master`/`tmon-filternak`, `--filter-nak`,
240 s), the set that has been through the full offline analysis pipeline. Later
desync captures (including the ramp runs in "Confirmation" below) show the same
shape but are not all re-analysed here.

### Method

For every desync run we take the reframed inner (whacker/rxcsniff) byte stream,
locate the exact byte where framing first breaks, and dump a wide window around
it — **±16 KB of raw bytes plus 48 parsed frames on each side** — so the
context can be analysed without going back to the multi-gigabyte pcap. The wide
window matters: an earlier ±256-byte window was too small to contain a single
USB **SOF** packet on either side, which made the key loss-vs-insertion check
come back empty and led us to a wrong preliminary conclusion.

Two independent time references are used:

- The **USB SOF stream** — the host emits a SOF packet every 125 µs (one per
  High-Speed microframe); the 11-bit frame *number* it carries increments once
  per 1 ms and is shared across the 8 microframes of a frame (confirmed: a 247 s
  capture contains exactly 120 wraps of the number). So the frame number gives
  1 ms resolution, and counting SOF packets since the last increment refines
  that to 125 µs. A jump across the break is real bus time — and real traffic —
  unaccounted for. *(The event-table gaps below are currently measured at the
  1 ms frame-number level; the 125 µs microframe refinement is not yet applied
  and would only sharpen each value, not change the picture.)*
- The **usbmon completion timestamp** — the host kernel's wall-clock time when
  each URB of OV3 data completed. Comparing "SOF-number span" against "usbmon
  wall-clock span" over a stretch of stream tells us whether that stretch was
  delivered in real time or faster (i.e. drained from a buffer).

### Q1 — where in the stream, and what kind of discontinuity is it?

The original question was "did the gateware lose bytes or inject/duplicate
them?" As shown below, the data supports neither cleanly, and points to a
third answer (**H**).

Per-event detail, regenerated from `results/manifest.jsonl` +
`results/sof_continuity.json`:

<!-- BEGIN event-table -->
| run | gw | byte offset | % of stream | skip B | SOF gap (ms) | pre->post PID | preR | postR |
|---|---|--:|--:|--:|--:|---|--:|--:|
| 20260904T180037Z | tmon-filternak | 7,092,614 | 0.5% | 261 | 2027 | DATA0 -> NYET | 4.11 | 1.00 |
| 20260904T183016Z | tmon-filternak | 7,298,207 | 0.5% | 420 | 45 | DATA0 -> NYET | 4.05 | 1.00 |
| 20260904T165121Z | bundled | 7,302,382 | 0.5% | 211 | 400 | DATA0 -> NYET | 4.08 | 1.00 |
| 20260904T181030Z | tmon-filternak | 10,792,347 | 0.7% | 227 | 1306 | DATA0 -> ACK | 4.16 | 1.00 |
| 20260904T174557Z | master | 12,849,978 | 0.9% | 408 | 1219 | DATA0 -> ACK | 4.02 | 1.00 |
| 20260904T182022Z | tmon-filternak | 14,190,868 | 1.0% | 262 | 387 | DATA1 -> ACK | 4.01 | 1.00 |
| 20260904T164128Z | bundled | 14,396,843 | 1.0% | 459 | 964 | DATA0 -> ACK | 4.10 | 1.00 |
| 20260904T172104Z | master | 16,454,024 | 1.1% | 112 | 712 | DATA0 -> NYET | 3.98 | 1.00 |
| 20260904T170621Z | bundled | 17,070,857 | 1.2% | 457 | 1153 | DATA0 -> ACK | 2.83 | 1.00 |
| 20260904T173603Z | master | 17,071,164 | 1.2% | 196 | 920 | DATA1 -> NYET | 2.80 | 1.00 |
| 20260904T170115Z | bundled | 24,987,229 | 1.7% | 315 | 214 | DATA0 -> ACK | 3.90 | 1.00 |
| 20260904T173057Z | master | 36,302,966 | 2.4% | 274 | 40 | DATA0 -> NYET | 4.20 | 1.00 |
<!-- END event-table -->

*`% of stream` = position of the break in the full ~1.5 GB inner stream. `skip
B` = bytes the reframer discarded to re-lock (LibOV's live framer discards a
comparable 260–770 bytes and also recovers). `SOF gap` = jump in the SOF frame
number across the break, in ms — the frame number increments once per 1 ms, so
the value is milliseconds directly (it is read mod 2048, so for the largest
entries the true gap could be that + a multiple of 2048 ms; wall-clock across
the seam is a lower bound at ~272 ms either way). `preR` / `postR` = SOF-number
span ÷ usbmon wall-clock span for the region before / after the break; ≈ 1 means
delivered in real time, ≫ 1 means drained from a buffer faster than real time.*

### Observations on the onset

The observations below are organised around one hypothesis, stated so it can be
checked and, if wrong, shown wrong. Each was gathered before the ramp test that
ultimately confirmed it ("Confirmation", below) — they are the indicators that
pointed there, and they are worth keeping as an independent line of support.

> **H: when the sniff session starts, the SDRAM capture ring is not empty. The
> host reads out the previous session's left-over bytes first, fast, until the
> reader catches up to where the current session is now writing. The visible
> "desync" is that seam.**

1. **Loss vs. injected data is the wrong question — and that is the finding.**
   Taken at face value the SOF frame number jumps 40 ms – ~2 s across the onset
   (event table), which reads as a large loss. But a 40 ms – 2 s stall in an
   FPGA-based capture pipe is not physically plausible, and there is no
   duplicate-of-neighbouring-bytes signature that would indicate injection or a
   stale re-read in place either. The magnitude is the tell: rather than one
   capture with a gap, this is the stream **switching source** at a point — the
   pre-onset bytes and the post-onset bytes come from different fills of the
   ring (**H**), and the SOF jump is the wall-clock distance between them, not
   traffic lost inside one session. So on the original loss-vs-extra-data axis
   the answer is *inconclusive*; the size of the gap is what pushes past it.
   **Falsified by:** a duplicate-bytes signature at the onset; SOF continuity
   across it (no jump); a plausible mechanism for a multi-hundred-ms real stall;
   or the pre-onset bytes proving to be live current-session capture after all
   (the `preR` evidence below argues against that).

2. **It happens early, and exactly once.** Every run desyncs once, between 0.5 %
   and 2.4 % into the ~1.5 GB stream — roughly 1–6 s into a 240 s capture. After
   re-locking, both the offline reframer and LibOV's live framer run clean to the
   end. (An earlier note that it was "millions of packets in" was wrong — that
   read an absolute byte offset as a packet count.)

3. **The bytes before the onset were not captured live — they were drained from
   a buffer.** For every event the pre-onset region has `preR ≈ 2.8–4.2`: it
   spans that many times more bus time (SOF milliseconds) than the wall-clock
   the host took to receive it. The post-onset region has `postR = 1.00` in
   every run — real-time. Control: three clean runs (1 reload, 2 no-load), split
   at the same ~10 MB point, show early-region `preR ≈ 0.4–0.7` — below 1, and
   4–10× lower than any desync run, so a fast early burst is *not* just normal.
   The pre-onset block is also internally near-continuous (0–3 SOF gaps, all
   ≤ 4 ms; clean runs by comparison carry ~45 gaps of ≤ 8 ms), and the onset gap
   is 5–250× larger than any of those. This is **H**'s central claim; it is
   consistent with the gateware: a non-drained teardown never zeroes the 16 MiB
   ring, and the next `GO` edges reset both the read and write pointers to
   `ring_base` (`sdram_host_read.py` / `sdram_sink.py`), so the reader starts on
   top of the old bytes and burst-drains them until it meets the writer.
   **Supported by:** drain-wait (which empties the ring tail at the previous
   teardown) eliminating the desync entirely (0/49). **Falsified by:** clean
   runs showing `preR ≈ 3` for their early region (they do not); or the
   ramp-signal test below showing the pre-onset payloads carry *current*-session
   values.

4. **RX-path overflow is concentrated entirely in the first quartile, then
   stops.** Splitting each desync run into four equal byte ranges: 10/12 runs
   have 137–700 `HF0_OVF` events, *all* in the first quartile; the other 2 runs
   have none; no run has any overflow in quartiles 2–4. Under **H** this is
   expected — the ring is full of stale data at session start, so the sink
   overflows against it until the reader drains past and frees space (the
   onset), after which the ring has headroom. The two zero-overflow runs are
   also the two with the lowest `preR` (2.80, 2.83) — the least backlog to
   drain. **Falsified by:** overflow spread through a desync run, or appearing
   in its later quartiles.

5. **No correlation with gateware version.** The three builds interleave through
   the offset-sorted event table with no grouping; the two runs that break
   within 307 bytes of the same offset (~17.07 MB) are *different* builds
   (`bundled`, `master`).

6. **The wall-clock cost of the seam is fixed.** Across all 12 events the usbmon
   wall-clock advances ~272 ms (272–289) between the last pre-onset byte and the
   first post-onset byte — independent of gateware and of the SOF-gap size. A
   fixed cost points to a fixed operation at the seam (a timeout or settle), not
   a variable stall. Not yet tied to a specific step in the gateware or client.

7. **The session-start marker is missing from the whole stream.** The gateware
   stuffs an `HF0_FIRST` marker on the `CSTREAM_CFG` enable edge, and LibOV
   gates all packet handling on having seen it; clean runs have exactly one, at
   packet #1. A direct scan (robust to the framing break) finds **no `HF0_FIRST`
   anywhere in any of the 12** — not displaced, absent. Under **H** a plausible
   reason is that a full ring at `CSTREAM_CFG` enable has no room to stuff the
   marker, but that is not confirmed; reported as an observation. Caveat on
   using the marker as a tell: one clean drain-wait run has also turned up with
   no `HF0_FIRST` and no desync.

8. **Byte context at the trip point (likely DUT-specific).** The break always
   lands inside the low-entropy zero/pad tail of a 520-byte data frame; the last
   valid frame before it decodes as a USB DATA0/DATA1 packet in all 12, and the
   first frame after re-lock as a handshake (ACK or NYET). These specifics may
   reflect this DUT's data and not generalise.

### Confirmation — a known ramp signal in the OUT stream

The observations above are all inference from timing. This test turns the
question into a direct read, and it **confirms H**.

**Method.** The OV3 sniffs both directions of the DUT's USB traffic, so a known
pattern played *to* the DUT lands in the capture as decodable OUT data packets,
giving the stream a ground-truth serial number it otherwise lacks. We play a
24-bit linear ramp (S24, sample value = sample index mod 2²⁴, same on every
channel) into the DUT via one **continuous** `aplay -D hw:<dut>` at 96 kHz,
native format, spanning the whole run of sniff sessions — a free-running,
wrap-counted absolute timeline. Offline, the OUT DATA packets are pulled from
the reframed stream and the DUT's S24↔on-wire bit-plane transform is inverted
(validated bit-exact against the driver's codec model first) to read the ramp
value per packet. The ramp is DC / sub-Hz and is blocked by the DUT's
DC-coupling caps, so nothing reaches the analog outputs. This is **not a new
scenario**: the DUT driver already runs playback URBs continuously (zero-filled
when idle), so the ramp changes only payload *entropy*, not bus timing or load,
and the framer keys on magic bytes, not content.

Under normal live capture the ramp advances ~10 frames per OUT packet, so across
a few-hundred-byte framing break it should barely move. If instead the pre-seam
packets carry ramp values from an *earlier* point on the timeline, the pre-seam
data predates the session — H confirmed. A ramp continuous across the seam would
falsify it.

**Result** (`--filter-nak`, no-load, ramp running):

| run | seam @ inner offset | ramp before → after | jump across the seam |
|---|--:|---|--:|
| `161234Z` | 7,195,244 | 7,981,234 → 12,661,784 | **+48.8 s** |
| `162331Z` | 16,245,862 | 3,987,940 → 8,593,220 | **+48.0 s** *(plus a +0.28 s step ~1 KB later — drain tail)* |
| `161840Z` | 263 (at stream start) | — no pre-seam region | ramp continuous through the whole capture |

The two runs with a substantial pre-seam region both show the ramp jumping
**~48 seconds forward** across the seam: the bytes before it are ~48 s older
than the bytes after it — **a previous session's data**, read straight off the
wire with no SOF-wrap or `preR` inference. The third run is the complementary
case: its seam is at byte 263, there is essentially no stale block, and the ramp
is continuous throughout — exactly what H predicts when the ring was nearly
empty at session start.

The ~48 s is consistent between the two runs, which suggests it is a
characteristic amount of timeline the ring holds — consistent with the previous
session's SDRAM sink continuing to write and wrap the ring after its client
detached, so the ring's contents span far more elapsed time than its 16 MiB
size alone.

*(More ramp captures are being collected; this table will grow.)*

---

## Conclusion

The ramp test confirms the hypothesis: the `--filter-nak` desync is the seam
where a new sniff session's reader, starting on top of the previous session's
un-cleared SDRAM ring, catches up to the live write position. It is an
initialisation problem — no gateware timing fault is involved. The fix belongs
at start-up (empty/clear the ring on capture-enable, in gateware or client),
not in the framer.

## Tooling

- `reframe.py` — offline reframer; `--blip-window` / `--context-frames` control
  the event-context dump; `iter_inner_frames()` for reuse.
- `reprocess.py` — re-run `reframe.py` over stored pcaps after a heuristic
  change; merges derived fields back into the manifest.
- `sof_continuity.py` — the SOF-number vs wall-clock `preR`/`postR` analysis.
- `scan_first_marker.py` — locate `HF0_FIRST`/`HF0_LAST` in a run's stream.
- `ramp_wav.py` — generate the S24 ramp WAV played into the DUT.
- `ploytec_out_decode.py` — inverse of the DUT's playback bit-plane encoder.
- `decode_out_ramp.py` — read the ramp out of the sniffed OUT packets and
  measure the ramp step across the seam.
- `aggregate.py` — per-scenario hit rates across all batches.
- `gen_report_tables.py` — regenerate the two data tables in this document
  (`--update issue25-report.md`). Rows captured against a disconnected DUT
  (< 100 KB reframed) are dropped automatically.
