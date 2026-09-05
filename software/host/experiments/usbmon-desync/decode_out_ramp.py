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
    records = list(reframe.read_pcap_records(pcap))
    tally = collections.Counter()
    for b, d, s, u, p in reframe.iter_bulk_in(records):
        tally[(b, d)] += len(p)
    (bus, dev), _ = tally.most_common(1)[0]
    chunks, meta, pos = [], [], 0
    for b, d, ts_s, ts_u, p in reframe.iter_bulk_in(records):
        if b == bus and d == dev:
            c = reframe.strip_ftdi(p)
            chunks.append(c)
            meta.append((pos, pos + len(c), ts_s, ts_u))
            pos += len(c)
    return b"".join(chunks), meta


def ramp_packets(inner):
    """[(inner_offset, base_ramp_value)] for every self-identified playback-ramp
    OUT packet in the inner rxcsniff stream."""
    out = []
    n = len(inner)
    c = 0
    for c in range(min(n, 8192)):
        _m, sz = reframe.inner_frame_size(inner[c:c + reframe.MAX_PACKET_SIZE + 8])
        if inner[c] in (0xA0, 0xA2) and sz not in (None, reframe._INCOMPLETE):
            break
    while c < n:
        _m, sz = reframe.inner_frame_size(inner[c:c + reframe.MAX_PACKET_SIZE + 8])
        if sz in (None, reframe._INCOMPLETE):
            c += 1
            continue
        d = blip_classify.decode_frame_packet(inner[c:c + sz])
        if d and d.get("pid_byte") in (0xC3, 0x4B):           # DATA0 / DATA1
            # payload = bytes after the header + delta_ts + PID byte
            dts_len = (inner[c + 3] >> 5) + 1
            pkt_start = 4 + dts_len
            payload = inner[c + pkt_start + 1:c + sz]         # skip PID
            if len(payload) >= PLAYBACK_AUDIO_BYTES:
                vals, agree = decode_out_packet_ramp(payload[:PLAYBACK_AUDIO_BYTES])
                if agree and len(vals) == PLAYBACK_FRAMES and _consecutive(vals):
                    out.append((c, vals[0]))
        c += sz
    return out


def _consecutive(vals):
    return all((vals[i + 1] - vals[i]) % RAMP_WRAP == 1 for i in range(len(vals) - 1))


def _delta(a, b):
    """signed shortest-path delta b-a on the mod-2**24 ring."""
    d = (b - a) % RAMP_WRAP
    return d - RAMP_WRAP if d > RAMP_WRAP // 2 else d


def analyze(pcap, seam_off=None):
    inner, _meta = reconstruct(pcap)
    rp = ramp_packets(inner)
    r = {"pcap": os.path.basename(pcap), "ramp_packets": len(rp)}
    if len(rp) < 4:
        r["error"] = "only %d ramp packets found" % len(rp)
        return r
    r["first_ramp"] = rp[0][1]
    r["last_ramp"] = rp[-1][1]
    # discontinuities: consecutive ramp packets should step by PLAYBACK_FRAMES
    breaks = []
    for (o0, v0), (o1, v1) in zip(rp, rp[1:]):
        step = _delta(v0, v1)
        if step != PLAYBACK_FRAMES:
            kind = ("dup" if step == 0 else "reorder/stale" if step < 0 else "gap")
            breaks.append({"offset": o1, "from": v0, "to": v1,
                           "step": step, "kind": kind})
    r["n_breaks"] = len(breaks)
    r["breaks"] = breaks[:20]
    if seam_off is not None:
        pre = [v for o, v in rp if o < seam_off]
        post = [v for o, v in rp if o >= seam_off]
        if pre and post:
            r["seam_pre_ramp"] = pre[-1]
            r["seam_post_ramp"] = post[0]
            r["seam_ramp_step"] = _delta(pre[-1], post[0])
            # H: pre-seam data is OLDER -> its ramp value is behind the
            # post-seam value by much more than the normal per-packet step
            r["pre_seam_is_earlier"] = r["seam_ramp_step"] not in range(
                0, PLAYBACK_FRAMES * 4)
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
        r = analyze(pcap, seam)
        results.append(r)
        if "error" in r:
            print("%-30s  %s" % (r["pcap"], r["error"]))
            continue
        print("%-30s ramp_pkts=%d  first=%d last=%d  breaks=%d%s"
              % (r["pcap"], r["ramp_packets"], r["first_ramp"], r["last_ramp"],
                 r["n_breaks"],
                 ("  seam step=%d pre_earlier=%s"
                  % (r["seam_ramp_step"], r["pre_seam_is_earlier"]))
                 if "seam_ramp_step" in r else ""))
        for b in r["breaks"]:
            print("    break @%d  %d -> %d  step=%d  (%s)"
                  % (b["offset"], b["from"], b["to"], b["step"], b["kind"]))

    if args.json:
        json.dump(results, open(args.json, "w"), indent=2)
        print("wrote", args.json)


if __name__ == "__main__":
    main()
