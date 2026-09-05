#!/usr/bin/env python3
"""Where (if anywhere) is HF0_FIRST in each desync run's inner stream, relative
to the drop?  #25 -- Frank: "maybe the location of the HF0_FIRST start packet
becomes important here."  If the current session's FIRST marker sits right
after the seam, that pins where the live capture actually starts.

Robust to the framing break: walks frames from a lock, and on any bad frame
also does a raw byte re-scan for the next 0xA0/0xA2 with flags & HF0_FIRST.
"""
import collections, json, os, sys
HERE = os.path.dirname(os.path.realpath(__file__)); sys.path.insert(0, HERE)
import reframe, blip_classify

HF0_FIRST = 0x10
HF0_LAST = 0x20


def inner_of(pcap):
    recs = list(reframe.read_pcap_records(pcap))
    tally = collections.Counter()
    for b, d, s, u, p in reframe.iter_bulk_in(recs):
        tally[(b, d)] += len(p)
    (bus, dev), _ = tally.most_common(1)[0]
    chunks = [reframe.strip_ftdi(p) for b, d, s, u, p in reframe.iter_bulk_in(recs)
              if b == bus and d == dev]
    return reframe.walk(b"".join(chunks), skip_startup=True, collect_magic=0xD0)["subpayload"] or b""


def scan(inner):
    """every (offset, 'FIRST'|'LAST') marker in the inner stream."""
    out = []
    n = len(inner)
    c = 0
    for c in range(min(n, 8192)):
        _m, sz = reframe.inner_frame_size(inner[c:c + 528])
        if inner[c] in (0xA0, 0xA2) and sz not in (None, -1):
            break
    while c < n:
        _m, sz = reframe.inner_frame_size(inner[c:c + 528])
        if sz in (None, -1):
            c += 1
            continue
        if inner[c] in (0xA0, 0xA2) and sz >= 4:
            fl = inner[c + 1]
            if fl & HF0_FIRST:
                out.append((c, "FIRST"))
            if fl & HF0_LAST:
                out.append((c, "LAST"))
        c += sz
    return out


def main():
    rows = [json.loads(l) for l in open(sys.argv[1])] if sys.argv[1].endswith(".jsonl") else None
    if rows is not None:
        jobs = [(r["tag"] + ".pcap", r.get("inner_first_offset"))
                for r in rows if r.get("inner_verdict") not in (None, "CLEAN")]
    else:
        jobs = [(p, None) for p in sys.argv[1:]]
    for pcap, drop in jobs:
        if not os.path.exists(pcap):
            print("MISSING", pcap); continue
        inner = inner_of(pcap)
        marks = scan(inner)
        firsts = [o for o, k in marks if k == "FIRST"]
        lasts = [o for o, k in marks if k == "LAST"]
        rel = ""
        if drop and firsts:
            rel = "  FIRST vs drop@%d: %s" % (drop, ", ".join(
                ("%+d" % (o - drop)) for o in firsts))
        print("%-26s len=%d  FIRST@%s  LAST@%s%s"
              % (os.path.basename(pcap), len(inner),
                 firsts or "-", lasts[-3:] or "-", rel))


if __name__ == "__main__":
    main()
