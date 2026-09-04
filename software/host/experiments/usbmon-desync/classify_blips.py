#!/usr/bin/env python3
"""Re-run blip_classify.classify_event() over every already-captured event.

Reads only the small JSON sidecars reframe.py writes under results/blips/
(each a few hundred bytes -- the saved window, frame lists, and offsets) --
never touches the source .pcap (can be gigabytes). Safe and fast to re-run
any time classify_event() gains a new heuristic; a full matrix's worth of
blips reclassifies in well under a second.

    ./classify_blips.py                    # every sidecar under results/blips
    ./classify_blips.py --dir results/blips
    ./classify_blips.py --dry-run          # report changes, write nothing

Updates each sidecar's "classification" field in place when it changes, and
prints a summary of what changed. Does NOT touch results/manifest.jsonl --
that's what its own "inner_first_dup_of_preceding" reflects the FIRST event's
classification *at capture time*; for anything beyond that, or a matrix-wide
view after reclassifying, read the sidecars (or extend this script -- it's a
natural place to add a report/aggregate mode alongside the reclassify pass).
"""

import argparse
import glob
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
import blip_classify  # noqa: E402

HERE = os.path.dirname(os.path.realpath(__file__))


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dir", default=os.path.join(HERE, "results/blips"))
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    sidecars = sorted(glob.glob(os.path.join(args.dir, "*.json")))
    if not sidecars:
        sys.exit("no blip sidecars found under %s (run_bisect.sh writes them "
                 "via --dump-blips)" % args.dir)

    print("reclassifying %d event(s) from %s ..." % (len(sidecars), args.dir))
    changed = 0
    for path in sidecars:
        with open(path) as f:
            ev = json.load(f)
        window = bytes.fromhex(ev["window_hex"])
        new_cls = blip_classify.classify_event(
            window, ev["trip_idx"], ev["run_length"], window_lo=ev["window_lo"],
            pre_frames=ev.get("pre_frames"), post_frames=ev.get("post_frames"))
        old_cls = ev.get("classification", {})
        if new_cls != old_cls:
            changed += 1
            print("  CHANGED %s\n    was: %s\n    now: %s"
                  % (os.path.basename(path), old_cls, new_cls))
            if not args.dry_run:
                ev["classification"] = new_cls
                with open(path, "w") as f:
                    json.dump(ev, f)

    verb = "would change" if args.dry_run else "changed"
    print("\n%d/%d sidecar(s) %s" % (changed, len(sidecars), verb))
    return 0


if __name__ == "__main__":
    sys.exit(main())
