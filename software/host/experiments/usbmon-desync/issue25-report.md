# `--filter-nak` sniff desync (ov_ftdi #25) — findings to date

*Living draft, revised as data comes in. Last data refresh: run
`./gen_report_tables.py --update issue25-report.md` after new captures or a
reprocess. This is the externally-shareable summary; day-to-day working notes,
dead ends and internal hypotheses live in `FINDINGS.md`.*

**Confidence note.** Everything here is backed by captured data, the OpenVizsla
gateware RTL, or LibOV source, and is flagged where it is still a hypothesis.
All captures use a **Reloop Jockey 3** as the sniffed device (DUT). It is a
High-Speed device with a fairly idle bus under `--filter-nak`, and its traffic
carries no timestamp or sequence field of its own, so some of the fine detail
below (packet types either side of the event, the byte pattern at the trip
point) may be specific to this DUT's data and not general. We have already
revised two conclusions in this investigation as better data arrived; treat a
tidy story as a prompt to check it further.

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
| bundled | no-load | 8 | 4 | 50% |
| master | no-load | 8 | 4 | 50% |
| tmon-filternak | no-load | 8 | 4 | 50% |
| bundled | no-load + drain-wait | 12 | 0 | 0% |
| master | no-load + drain-wait | 9 | 0 | 0% |
| tmon-filternak | no-load + drain-wait | 8 | 0 | 0% |
| bundled | reload + drain-wait | 1 | 0 | 0% |
| master | reload + drain-wait | 2 | 0 | 0% |
| tmon-filternak | reload + drain-wait | 1 | 0 | 0% |
| | | | | |
| **all** | **reload** | **24** | **0** | **0%** |
| **all** | **no-load** | **24** | **12** | **50%** |
| **all** | **no-load + drain-wait** | **29** | **0** | **0%** |
| **all** | **reload + drain-wait** | **4** | **0** | **0%** |
<!-- END scenario-table -->

*"reload" = FPGA reconfigured from the bitstream before the run. "no-load" = the
bitstream left as-is from the previous run. "drain-wait" = every session,
including the one before it, waited for the `HF0_LAST` marker before releasing
the SDRAM read/sink path at teardown, instead of disabling it immediately.
Gateware builds: `bundled` = the 2024 bitstream shipped in the fwpkg; `master` =
current git master; `tmon-filternak` = desowin's `tmon-nordic/filter-nak`
branch.*

### Observations

1. **The desync only occurs when the FPGA was not reconfigured before the run.**
   0/24 with reload, 12/24 without. Every reload cell is clean.
2. **Making the previous session drain cleanly eliminates it.** 0/29 no-load
   runs desync when the prior session waited for `HF0_LAST` before tearing down
   the SDRAM path, versus 12/24 (50%) without that wait. The priming
   reload+drain runs are counted in the table and are also clean.
3. **The three gateware builds behave the same.** Same ~50% no-load rate on
   each; reload and drain-wait clean on each. None of the gateware differences
   we tested changes the outcome.
4. **RX-path overflow (`HF0_OVF`) is present but does not track the desync.** It
   fires on clean reload runs too, at a similar rate, so "saw overflow" and
   "desynced" are independent here. Its in-band flag count and `ovctl`'s
   register-read overflow count also disagree sharply on the no-load runs
   (nonzero in-band on 22/24, zero via the register on 0/24) — noted for
   completeness; we do not think overflow is the mechanism behind #25 and are
   not relying on it in the discussion below.

### Discussion — no-load vs reload vs drain

Reload and "previous session drained" both fix the symptom, and the common
thread is the state the SDRAM capture path is left in between sessions. A
reconfigure clears that state wholesale; a clean drain empties it. Leaving it
alone is what fails.

From an application's point of view this matters because **a sniff tool has no
control over how the previous tool left the device.** If a non-empty / not-fully
reset capture path can corrupt the next session's stream, then either the client
must force a known-good starting state (drain or reconfigure) as part of *start*,
or the gateware must guarantee one on capture-enable. Relying on "the last user
shut down tidily" is not something a tool can depend on.

---

## 3. Deep-dive: the onset of the desync

### Method

For every desync run we take the reframed inner (whacker/rxcsniff) byte stream,
locate the exact byte where framing first breaks, and dump a wide window around
it — **±16 KB of raw bytes plus 48 parsed frames on each side** — so the
context can be analysed without going back to the multi-gigabyte pcap. The wide
window matters: an earlier ±256-byte window was too small to contain a single
USB **SOF** packet on either side, which made the key loss-vs-insertion check
come back empty and led us to a wrong preliminary conclusion.

Two independent time references are used:

- The **USB SOF frame number** — an 11-bit counter the host emits on the wire,
  incrementing once per 1 ms frame (the OV3 captures a SOF packet every 125 µs,
  but the *number* is shared across the 8 microframes of a frame; confirmed
  because a 247 s capture contains exactly 120 wraps of the counter). A jump in
  this number across the break is real bus time — and real traffic —
  unaccounted for.
- The **usbmon completion timestamp** — the host kernel's wall-clock time when
  each URB of OV3 data completed. Comparing "SOF-number span" against "usbmon
  wall-clock span" over a stretch of stream tells us whether that stretch was
  delivered in real time or faster (i.e. drained from a buffer).

### Q1 — where in the stream, and is it loss or extra data?

Per-event detail, regenerated from `results/manifest.jsonl` +
`results/sof_continuity.json`:

<!-- BEGIN event-table -->
| run | gw | byte offset | % of stream | skip B | SOF gap (ms) | pre->post PID | preR | postR |
|---|---|--:|--:|--:|--:|---|--:|--:|
| 20260904T180037Z | tmon-filternak | 7,092,614 | 0.5% | 261 | 2027 | DATA0 -> NYET | 4.13 | 1.00 |
| 20260904T183016Z | tmon-filternak | 7,298,207 | 0.5% | 420 | 45 | DATA0 -> NYET | 4.05 | 1.00 |
| 20260904T165121Z | bundled | 7,302,382 | 0.5% | 211 | 400 | DATA0 -> NYET | 4.10 | 1.00 |
| 20260904T181030Z | tmon-filternak | 10,792,347 | 0.7% | 227 | 1306 | DATA0 -> ACK | 4.18 | 1.00 |
| 20260904T174557Z | master | 12,849,978 | 0.9% | 408 | 1219 | DATA0 -> ACK | 4.01 | 1.00 |
| 20260904T182022Z | tmon-filternak | 14,190,868 | 1.0% | 262 | 387 | DATA1 -> ACK | 4.03 | 1.00 |
| 20260904T164128Z | bundled | 14,396,843 | 1.0% | 459 | 964 | DATA0 -> ACK | 4.10 | 1.00 |
| 20260904T172104Z | master | 16,454,024 | 1.1% | 112 | 712 | DATA0 -> NYET | 3.99 | 1.00 |
| 20260904T170621Z | bundled | 17,070,857 | 1.2% | 457 | 1153 | DATA0 -> ACK | 2.85 | 1.00 |
| 20260904T173603Z | master | 17,071,164 | 1.2% | 196 | 920 | DATA1 -> NYET | 2.81 | 1.00 |
| 20260904T170115Z | bundled | 24,987,229 | 1.7% | 214 | 214 | DATA0 -> ACK | 3.89 | 1.00 |
| 20260904T173057Z | master | 36,302,966 | 2.4% | 274 | 40 | DATA0 -> NYET | 4.18 | 1.00 |
<!-- END event-table -->

*`% of stream` = position of the break in the full ~1.5 GB inner stream. `skip
B` = bytes the reframer discarded to re-lock (LibOV's live framer discards a
comparable 260–770 bytes and also recovers). `SOF gap` = jump in the SOF frame
number across the break, in ms (mod 2048; for the larger values the true gap may
be that + a multiple of 2048 ms). `preR` / `postR` = ratio of SOF-number span to
usbmon wall-clock span for the region before / after the break.*

### Observations on the onset

1. **It is data loss, not injected/extra data.** Every event shows a real SOF
   frame-number discontinuity — 40 ms to ~2 s of bus time (and therefore real
   captured traffic) missing across the break. The number of bytes the reframer
   skips to re-lock (110–460) is unrelated to the size of that gap; the skip is
   just the local cost of finding the next frame anchor, not a measure of the
   loss. There is no duplicate-of-neighbouring-bytes signature, so nothing
   points to stale data being *re-read* in place either.

2. **It happens early, and once.** Every run desyncs exactly once, between 0.5 %
   and 2.4 % into the stream — roughly 1–6 s into a 240 s capture. After
   re-locking, both the offline reframer and LibOV's live framer run clean to
   the end. (An earlier note that it was "millions of packets in" was wrong; it
   was reading an absolute byte offset, not a packet count.)

3. **The data *before* the break was not captured live.** For every event, the
   region before the break has `preR ≈ 3–4`: it spans 3–4× more bus time (SOF
   milliseconds) than the wall-clock time the host took to receive it — i.e. it
   was delivered as a fast drain of buffered data. The region *after* the break
   has `postR = 1.00` in every run: real-time delivery. The pre-break region is
   also internally continuous (no missing SOF milliseconds within it) and is
   followed by a single clean jump. **Working hypothesis (matches desowin's):
   the SDRAM ring was not empty when the session started — the pre-break bytes
   are left over from the previous session, read out fast until the reader
   catches up to where the current session is actually writing (the break), and
   the "loss" is that seam.** A gateware-level mechanism is consistent with
   this: a non-drained teardown never zeroes the 16 MiB ring, and on the next
   `GO` edge both the read and write pointers reset to `ring_base` (per
   `sdram_host_read.py` / `sdram_sink.py`), so the reader starts on top of the
   old bytes. *(A control check — does a clean run's early region also show
   `preR ≈ 3`? — is in progress; if it does, fast early delivery is just normal
   and this argument weakens.)*

4. **No correlation with gateware version.** The three builds are interleaved
   through the offset-sorted table with no grouping; the two runs that break
   within 307 bytes of the same offset (~17.07 MB) are different builds
   (`bundled` and `master`).

5. **The wall-clock cost of the break is fixed.** Across all 12 events the
   usbmon wall-clock advances ~272 ms (272–289) between the last pre-break byte
   and the first post-break byte, regardless of gateware and regardless of the
   SOF-gap size. A fixed ~272 ms cost points to a fixed operation at the seam (a
   timeout or settle), not a variable stall.

6. **The session-start marker is missing.** LibOV stuffs an `HF0_FIRST` marker
   packet on the `CSTREAM_CFG` enable edge, and gates all packet handling on
   having seen it. Clean runs have exactly one, at packet #1. **All 12 desync
   runs have none at all.** This is consistent with the marker being generated
   at the current session's true start — i.e. at or inside the seam — and lost
   with the rest of the gap. *(Exact-location scan of every desync run's stream
   in progress.)* One caveat: a single clean drain-wait run has also now turned
   up with no `HF0_FIRST` and no desync, so a missing marker is not on its own a
   guarantee of trouble.

7. **Byte context at the trip point (likely DUT-specific).** The break always
   lands inside the low-entropy zero/pad tail of a 520-byte data frame; the last
   valid frame before it decodes as a USB DATA0/DATA1 packet in all 12, and the
   first frame after re-lock as a handshake (ACK or NYET). These specifics may
   reflect this DUT's idle-bus data and not generalise.

---

## Tooling

- `reframe.py` — offline reframer; `--blip-window` / `--context-frames` control
  the event-context dump.
- `reprocess.py` — re-run `reframe.py` over stored pcaps after a heuristic
  change; merges derived fields back into the manifest.
- `sof_continuity.py` — the SOF-number vs wall-clock `preR`/`postR` analysis.
- `scan_first_marker.py` — locate `HF0_FIRST`/`HF0_LAST` in a run's stream.
- `aggregate.py` — per-scenario hit rates across all batches.
- `gen_report_tables.py` — regenerate the two tables in this document.
