#!/usr/bin/env python3
"""Is the data *before* a desync drop part of the current sniff, or stale
left-over from a previous session?  (OpenVizslaTNG/ov_ftdi#25, Tomasz's
"where is the capture start marker / was the buffer empty to begin with".)

The USB SOF frame number is an 11-bit counter the *host* the DUT is plugged
into emits once per 125us bus frame -- the OpenVizsla only passively copies
it off the wire.  In a no-load run nothing touches the DUT's USB link
between sniff sessions, so that counter is a free-running clock independent
of when the OV3 capture path is started/stopped.  Two things then tell the
story, and they partition three ways, not two:

  1. wall-clock (usbmon completion time) delta ACROSS the drop, vs. the SOF
     frame-number gap across the drop.
  2. the "SOF frames per second of wall-clock" ratio for the region BEFORE
     the drop, vs. the same ratio for the region AFTER it (the post-drop
     region is 98% of the stream and runs to the end of a 240s capture --
     an unambiguous in-run control for "live" delivery; no clean run needed).

     wall-clock across drop | pre-ratio vs post-ratio | reading
     ---------------------- | ----------------------- | -------
     ~= SOF gap             | ~= equal                | device genuinely quiet
                            |                         |  -- real loss in real time
     << SOF gap             | ~= equal                | loss happened INSIDE the
                            |                         |  OV3 while the DUT kept talking
     << SOF gap             | pre >> post             | stale data ahead of the
                            |                         |  boundary (Tomasz's hypothesis)

The 11-bit counter wraps every 2048 frames (256ms), so unwrapping is only
safe WITHIN a region where step==1 holds throughout -- continuity is checked
and violations reported first, and the sequence is never unwrapped across
the drop.

Reuses reframe.py's pcap->stream/inner-stream/wallclock plumbing verbatim
(no re-implemented framing) and blip_classify.decode_frame_packet for the
SOF field.  Drop offsets come from each run's <tag>.reframe.json (written by
reframe.py), so run a wide-window reprocess first if the .reframe.json is
stale.

    ./sof_continuity.py results/ovctl-20260904T164128Z.pcap [more.pcap ...]
    ./sof_continuity.py --manifest results/manifest.analysis.jsonl
"""

import argparse
import collections
import json
import os
import sys

HERE = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, HERE)

import reframe          # noqa: E402
import blip_classify    # noqa: E402

# The OV3 captures a SOF packet every 125 us (one per HS microframe, ~8000/s),
# but the 11-bit *frame number* field only increments every 1 ms -- it's the
# millisecond frame count, shared across all 8 microframes of a frame.
# Verified: a 247 s capture implies 120 wraps of the counter (247000 ms /
# 2048), which only holds at 1 ms/increment. So a SOF-number delta of N is N
# milliseconds of bus time, and consecutive captured SOFs step by 0 or 1.
FRAME_MS = 1.0          # ms per SOF frame-number increment
WRAP = 2048             # 11-bit SOF frame number


def reconstruct(pcap):
    """pcap -> (outer_stream_bytes, chunk_meta) for the busiest bulk-IN dev.
    Lifted from reframe.main()'s two-pass reconstruction, no behavior change."""
    records = list(reframe.read_pcap_records(pcap))
    tally = collections.Counter()
    for bus, dev, _s, _u, payload in reframe.iter_bulk_in(records):
        tally[(bus, dev)] += len(payload)
    if not tally:
        sys.exit("no bulk-IN completions with data in %s" % pcap)
    (bus, dev), _ = tally.most_common(1)[0]
    chunks, chunk_meta, pos = [], [], 0
    for b, d, ts_s, ts_u, payload in reframe.iter_bulk_in(records):
        if b == bus and d == dev:
            c = reframe.strip_ftdi(payload)
            chunks.append(c)
            chunk_meta.append((pos, pos + len(c), ts_s, ts_u))
            pos += len(c)
    return b"".join(chunks), chunk_meta


def inner_sofs(inner):
    """[(inner_offset, sof_frame_num)] for every SOF packet in the inner
    (concatenated 0xD0-payload) rxcsniff stream, in order."""
    out = []
    n = len(inner)
    c = 0
    # match reframe.walk_inner's start-of-stream lock
    for c in range(min(n, 8192)):
        _m, sz = reframe.inner_frame_size(inner[c:c + 520 + 8])
        if inner[c] in (0xA0, 0xA1, 0xA2, 0xAC, 0xAD) and sz not in (None, -1):
            break
    while c < n:
        _m, sz = reframe.inner_frame_size(inner[c:c + 520 + 8])
        if sz in (None, -1) or sz == 0:
            c += 1
            continue
        d = blip_classify.decode_frame_packet(inner[c:c + sz])
        if d and d.get("sof_frame_num") is not None:
            out.append((c, d["sof_frame_num"]))
        c += sz
    return out


def continuity(sofs):
    """(violations, total_steps) -- consecutive captured SOF numbers should
    step by 0 (another microframe of the same ms frame) or 1 (next ms). A
    step of 2+ mod 2048 means one or more whole milliseconds have no SOF at
    all between these two -- a real gap."""
    v = 0
    for (_o0, a), (_o1, b) in zip(sofs, sofs[1:]):
        if (b - a) % WRAP >= 2:
            v += 1
    return v, max(0, len(sofs) - 1)


def unwrap(sofs):
    """cumulative frame index across a region assumed step==1-continuous
    (call continuity() first). Returns list parallel to sofs."""
    if not sofs:
        return []
    acc = [sofs[0][1]]
    for (_o0, a), (_o1, b) in zip(sofs, sofs[1:]):
        step = (b - a) % WRAP
        acc.append(acc[-1] + step)
    return acc


def wc_of_inner(off, segments, chunk_meta):
    oo = reframe.outer_offset_of_inner(segments, off)
    return reframe.wallclock_at(chunk_meta, oo) if oo is not None else None


def analyze(pcap, drop_first, drop_last):
    stream, chunk_meta = reconstruct(pcap)
    res = reframe.walk(stream, skip_startup=True, collect_magic=0xD0)
    inner = res["subpayload"] or b""
    segments = res.get("subpayload_segments")
    sofs = inner_sofs(inner)
    if len(sofs) < 10:
        return {"pcap": pcap, "error": "only %d SOFs found" % len(sofs)}

    pre = [s for s in sofs if s[0] < drop_first]
    post = [s for s in sofs if s[0] >= drop_last]
    r = {"pcap": os.path.basename(pcap), "n_sof": len(sofs),
         "n_pre": len(pre), "n_post": len(post),
         "drop_first": drop_first, "drop_last": drop_last}
    if len(pre) < 5 or len(post) < 5:
        r["error"] = "pre/post too small (%d/%d)" % (len(pre), len(post))
        return r

    pre_v, pre_steps = continuity(pre)
    post_v, post_steps = continuity(post)
    r["pre_continuity_violations"] = pre_v
    r["post_continuity_violations"] = post_v
    r["pre_steps"] = pre_steps
    r["post_steps"] = post_steps

    # region spans: SOF-number advance (= ms of bus time) vs usbmon wall-clock
    # elapsed (also ms) over the same byte range. ratio ~= 1 => that region was
    # delivered to the host in real time (live). ratio >> 1 => the region's
    # frames span more bus time than the host took to receive them, i.e. a
    # backlog / stale burst being drained.
    def region(seg):
        o0, _n0 = seg[0]
        oN, _nN = seg[-1]
        wc0 = wc_of_inner(o0, segments, chunk_meta)
        wcN = wc_of_inner(oN, segments, chunk_meta)
        uw = unwrap(seg)
        sof_ms = uw[-1] - uw[0]                       # SOF-number advance == ms of bus time
        if wc0 is None or wcN is None or wcN <= wc0:
            return sof_ms, None, None
        wc_ms = (wcN - wc0) * 1e3
        return sof_ms, wc_ms, sof_ms / wc_ms if wc_ms else None

    r["pre_sof_ms"], r["pre_wc_ms"], r["pre_ratio"] = region(pre)
    r["post_sof_ms"], r["post_wc_ms"], r["post_ratio"] = region(post)

    # across the drop: last pre SOF -> first post SOF
    (o_lastpre, s_lastpre) = pre[-1]
    (o_firstpost, s_firstpost) = post[0]
    wc_lastpre = wc_of_inner(o_lastpre, segments, chunk_meta)
    wc_firstpost = wc_of_inner(o_firstpost, segments, chunk_meta)
    # SOF-number gap across the drop == milliseconds of bus time missing
    # (mod 2048 -- so it's the true gap only if < 2048 ms; wrap_k_est below
    # says how many extra 2048 ms the wall-clock implies).
    r["sof_gap_ms_mod"] = (s_firstpost - s_lastpre) % WRAP
    if wc_lastpre is not None and wc_firstpost is not None:
        wc_dt_ms = (wc_firstpost - wc_lastpre) * 1e3
        r["wc_gap_ms"] = round(wc_dt_ms, 1)
        r["wrap_k_est"] = round((wc_dt_ms - r["sof_gap_ms_mod"]) / WRAP)
    return r


def load_drops_from_reframe_json(tag):
    j = tag + ".reframe.json"
    if not os.path.exists(j):
        return None
    with open(j) as f:
        d = json.load(f)
    inner = d.get("inner") or {}
    evs = inner.get("events") or []
    if not evs:
        return None
    e = evs[0]
    return e["first_offset"], e.get("last_offset", e["first_offset"])


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcap", nargs="*")
    ap.add_argument("--manifest",
                    help="take the pcap list + drop offsets from this manifest's "
                         "desync rows instead of positional args")
    ap.add_argument("--json", metavar="FILE", help="also write per-run dicts here")
    ap.add_argument("--split-at", type=int, metavar="INNER_OFFSET",
                    help="for positional pcaps: split the SOF list at this inner-"
                         "stream offset instead of reading a drop from "
                         "<tag>.reframe.json. Use on CLEAN runs to get a control "
                         "preR/postR -- if a clean run also shows preR>>1 for its "
                         "early half, a fast early-delivery burst is just normal "
                         "and preR proves nothing about stale data.")
    args = ap.parse_args()

    jobs = []   # (pcap, drop_first, drop_last)
    if args.manifest:
        with open(args.manifest) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                row = json.loads(line)
                if row.get("inner_verdict") in (None, "CLEAN"):
                    continue
                pcap = row["tag"] + ".pcap"
                df = row.get("inner_first_offset")
                drops = load_drops_from_reframe_json(row["tag"])
                dl = drops[1] if drops else df
                if df is not None and os.path.exists(pcap):
                    jobs.append((pcap, df, dl))
    for p in args.pcap:
        if args.split_at is not None:
            jobs.append((p, args.split_at, args.split_at))
            continue
        tag = p[:-5] if p.endswith(".pcap") else p
        drops = load_drops_from_reframe_json(tag)
        if not drops:
            sys.exit("no %s.reframe.json with an event -- reprocess first" % tag)
        jobs.append((p, drops[0], drops[1]))

    if not jobs:
        sys.exit("nothing to do")

    results = []
    hdr = ("%-28s %6s %8s %8s  %5s %5s  %8s %9s %4s  %7s %7s"
           % ("run", "npre", "preViol", "postViol", "", "",
              "SOFgapms", "wcGap_ms", "k", "preR", "postR"))
    print(hdr)
    print("-" * len(hdr))
    for pcap, df, dl in jobs:
        r = analyze(pcap, df, dl)
        results.append(r)
        if "error" in r:
            print("%-28s  ERROR: %s" % (r["pcap"], r["error"]))
            continue
        print("%-28s %6d %8d %8d  %5s %5s  %8s %9s %4s  %7s %7s"
              % (r["pcap"].replace(".pcap", ""), r["n_pre"],
                 r["pre_continuity_violations"], r["post_continuity_violations"],
                 "", "",
                 r["sof_gap_ms_mod"], r.get("wc_gap_ms", "?"),
                 r.get("wrap_k_est", "?"),
                 ("%.2f" % r["pre_ratio"]) if r.get("pre_ratio") else "?",
                 ("%.2f" % r["post_ratio"]) if r.get("post_ratio") else "?"))

    if args.json:
        with open(args.json, "w") as f:
            json.dump(results, f, indent=2)
        print("\nwrote %s" % args.json)


if __name__ == "__main__":
    main()
