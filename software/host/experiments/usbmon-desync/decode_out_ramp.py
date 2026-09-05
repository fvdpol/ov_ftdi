#!/usr/bin/env python3
"""Read the ramp signal out of the sniffed OUT (playback) packets of a #25
capture, and check it for continuity across the framing-break seam.

Depends on a ramp being played into the DUT during the sniff (see ramp_wav.py).
Playback OUT DATA packets carry 10 frames * 48 wire bytes of bit-plane audio;
`ploytec_out_decode.decode_out_packet_ramp` turns those back into 10 ramp
values. A playback-ramp packet is self-identifying: after decoding, all four
channels agree and the 10 values are ten consecutive integers (mod 2**24), so
we don't need to parse USB tokens/endpoints to find them.

Per capture, this reports:
  - the ramp value at the start and end of the stream (an absolute timeline,
    since aplay runs free across sessions),
  - every discontinuity in the ramp: gap (loss), repeat (duplication),
    decrease (reorder / stale data), with its stream offset,
  - the ramp step across the framing-break seam (from <tag>.reframe.json), and
    whether the pre-seam ramp values are EARLIER on the timeline than the
    post-seam ones -- the direct test of hypothesis H.

    ./decode_out_ramp.py results/<tag>.pcap
    ./decode_out_ramp.py --manifest results/manifest.analysis.jsonl

STATUS: first cut, not yet run against a real ramp capture -- the
packet-identification heuristic and the OUT-payload offset within the rxcsniff
record may need adjustment once we have one.
"""

import argparse
import collections
import json
import os
import sys

HERE = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, HERE)

import reframe                       # noqa: E402
import blip_classify                # noqa: E402
from ploytec_out_decode import (    # noqa: E402
    decode_out_packet_ramp, PLAYBACK_FRAMES, PLAYBACK_AUDIO_BYTES, RAMP_WRAP)

MIN_DATA_PAYLOAD = PLAYBACK_AUDIO_BYTES + 1     # PID + 480 audio bytes, minimum


def reconstruct(pcap):
    """pcap -> the INNER (0xD0-deframed) rxcsniff stream, same as reframe.py's
    walk_inner input. Offsets returned by ramp_packets() are in this stream,
    matching <tag>.reframe.json's inner event `first_offset`."""
    records = list(reframe.read_pcap_records(pcap))
    tally = collections.Counter()
    for b, d, s, u, p in reframe.iter_bulk_in(records):
        tally[(b, d)] += len(p)
    (bus, dev), _ = tally.most_common(1)[0]
    chunks = [reframe.strip_ftdi(p)
              for b, d, ts_s, ts_u, p in reframe.iter_bulk_in(records)
              if b == bus and d == dev]
    res = reframe.walk(b"".join(chunks), skip_startup=True, collect_magic=0xD0)
    return res["subpayload"] or b"", None


def ramp_packets(inner, ranges=None):
    """[(inner_offset, base_ramp_value)] for every self-identified playback-ramp
    OUT packet in the inner rxcsniff stream. Alignment comes from
    `reframe.iter_inner_frames` (the validated contiguous walk -- no hand-rolled
    mid-stream re-lock); `ranges` (list of (lo, hi)) restricts only the slow
    bit-plane ramp decode, not the walk. None = whole stream.
    """
    n = len(inner)
    if ranges is None:
        ranges = [(0, n)]
    ranges = sorted((max(0, lo), min(n, hi)) for lo, hi in ranges)
    out = []
    for c, name, sz in reframe.iter_inner_frames(inner):
        if not any(lo <= c < hi for lo, hi in ranges):
            continue
        if inner[c] not in (0xA0, 0xA2):
            continue
        d = blip_classify.decode_frame_packet(inner[c:c + sz])
        if not (d and d.get("pid_byte") in (0xC3, 0x4B)):     # DATA0 / DATA1
            continue
        dts_len = (inner[c + 3] >> 5) + 1
        pkt_start = 4 + dts_len
        payload = inner[c + pkt_start + 1:c + sz]             # skip PID
        if len(payload) < PLAYBACK_AUDIO_BYTES:
            continue
        vals, agree = decode_out_packet_ramp(payload[:PLAYBACK_AUDIO_BYTES])
        if agree and len(vals) == PLAYBACK_FRAMES and _consecutive(vals):
            out.append((c, vals[0]))
    return out


def _consecutive(vals):
    return all((vals[i + 1] - vals[i]) % RAMP_WRAP == 1 for i in range(len(vals) - 1))


def _delta(a, b):
    """signed shortest-path delta b-a on the mod-2**24 ring."""
    d = (b - a) % RAMP_WRAP
    return d - RAMP_WRAP if d > RAMP_WRAP // 2 else d


def analyze(pcap, seam_off=None, window=8_000_000, full=False):
    inner, _meta = reconstruct(pcap)
    n = len(inner)
    if full or seam_off is None:
        ranges = None
        edge = None
    else:
        # a small slice at each stream end (for the absolute-timeline endpoints)
        # plus a wide window around the seam (for the actual test).
        edge = 2_000_000
        ranges = [(0, edge),
                  (seam_off - window, seam_off + window),
                  (n - edge, n)]
    rp = ramp_packets(inner, ranges)
    rp.sort()
    r = {"pcap": os.path.basename(pcap), "ramp_packets": len(rp),
         "windowed": ranges is not None, "stream_len": n, "seam_off": seam_off}
    if len(rp) < 4:
        r["error"] = "only %d ramp packets found" % len(rp)
        return r
    r["first_ramp"] = rp[0][1]
    r["last_ramp"] = rp[-1][1]
    # Discontinuities between consecutive ramp OUT packets. Expected step is
    # PLAYBACK_FRAMES (10). Small deviations (tens of frames) are ordinary
    # playback-side jitter from the aplay feed and are counted but not
    # detailed. A real stale-session seam is a huge step (seconds of ramp, up
    # to a full 2**24 wrap) -- that is what SIGNIFICANT flags. In windowed
    # mode, pairs separated by a big byte gap straddle an un-scanned region
    # and are skipped.
    SIGNIFICANT = 2000          # frames (~20 ms at 96 kHz) -- well above jitter
    jitter = 0
    breaks = []
    for (o0, v0), (o1, v1) in zip(rp, rp[1:]):
        if r["windowed"] and (o1 - o0) > 200_000:
            continue
        step = _delta(v0, v1)
        if step == PLAYBACK_FRAMES:
            continue
        if abs(step - PLAYBACK_FRAMES) < SIGNIFICANT:
            jitter += 1
            continue
        kind = ("dup" if step == 0 else "reorder/stale/earlier" if step < 0
                else "gap/jump")
        breaks.append({"offset": o1, "from": v0, "to": v1,
                       "step": step, "kind": kind})
    r["jitter_breaks"] = jitter
    r["n_significant_breaks"] = len(breaks)
    r["breaks"] = breaks[:20]
    if seam_off is not None:
        pre = [(o, v) for o, v in rp if o < seam_off]
        post = [(o, v) for o, v in rp if o >= seam_off]
        if pre and post:
            r["seam_pre_ramp"] = pre[-1][1]
            r["seam_post_ramp"] = post[0][1]
            r["seam_pre_off"] = pre[-1][0]
            r["seam_post_off"] = post[0][0]
            step = _delta(pre[-1][1], post[0][1])
            r["seam_ramp_step_frames"] = step
            r["seam_ramp_step_ms"] = round(step / 96.0, 1)     # 96 frames/ms @96k
            # H: pre-seam data is an EARLIER part of the timeline than post-seam
            # -> stepping forward from pre to post is much more than the normal
            # per-packet advance (or negative, if pre is 'ahead' only via wrap).
            r["pre_seam_is_earlier"] = abs(step - PLAYBACK_FRAMES) >= 2000
    return r


def seam_of(tag):
    j = tag + ".reframe.json"
    if not os.path.exists(j):
        return None
    ev = (json.load(open(j)).get("inner") or {}).get("events") or []
    return ev[0]["first_offset"] if ev else None


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcap", nargs="*")
    ap.add_argument("--manifest")
    ap.add_argument("--json")
    ap.add_argument("--full", action="store_true",
                    help="decode the whole stream (slow) instead of windows "
                         "around the seam and the two stream ends")
    ap.add_argument("--window", type=int, default=8_000_000,
                    help="bytes each side of the seam to decode (default 8M)")
    args = ap.parse_args()

    jobs = []
    if args.manifest:
        for line in open(args.manifest):
            if not line.strip():
                continue
            row = json.loads(line)
            p = row["tag"] + ".pcap"
            if os.path.exists(p):
                jobs.append((p, seam_of(row["tag"])))
    for p in args.pcap:
        jobs.append((p, seam_of(p[:-5] if p.endswith(".pcap") else p)))
    if not jobs:
        sys.exit("nothing to do")

    results = []
    for pcap, seam in jobs:
        r = analyze(pcap, seam, window=args.window, full=args.full)
        results.append(r)
        if "error" in r:
            print("%-30s  %s" % (r["pcap"], r["error"]))
            continue
        print("%-30s ramp_pkts=%d  first=%d last=%d  jitter=%d significant=%d%s"
              % (r["pcap"], r["ramp_packets"], r["first_ramp"], r["last_ramp"],
                 r.get("jitter_breaks", 0), r.get("n_significant_breaks", 0),
                 ("\n    SEAM: pre_ramp=%d post_ramp=%d  step=%d frames (%.1f ms)"
                  "  -> pre-seam data is EARLIER on the timeline: %s"
                  % (r["seam_pre_ramp"], r["seam_post_ramp"],
                     r["seam_ramp_step_frames"], r["seam_ramp_step_ms"],
                     r["pre_seam_is_earlier"]))
                 if "seam_ramp_step_frames" in r else ""))
        for b in r["breaks"]:
            print("    significant break @%d  %d -> %d  step=%d frames  (%s)"
                  % (b["offset"], b["from"], b["to"], b["step"], b["kind"]))

    if args.json:
        json.dump(results, open(args.json, "w"), indent=2)
        print("wrote", args.json)


if __name__ == "__main__":
    main()
