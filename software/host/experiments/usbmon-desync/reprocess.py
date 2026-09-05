#!/usr/bin/env python3
"""Re-run reframe.py's analysis against already-captured pcaps, in place.

Capture (run_bisect.sh: usbmon + client + one reframe.py pass) and analysis
(reframe.py alone, over a stored .pcap) are already separate steps -- this is
the tool for re-running just the second one, as the heuristics in reframe.py
get refined while we learn more about the upsets. No hardware, no rig time,
safe to run any time, any number of times.

For each matching manifest row: re-invoke reframe.py against that row's
`.pcap` with the *current* reframe.py, refreshing `<tag>.verdict.txt`,
`<tag>.reframe.json`, and its files under results/blips/ -- then merge the
freshly derived fields (verdict, event offsets, wallclock, loss-vs-insertion
hint, ...) back into that row of manifest.jsonl. Capture-time facts (scenario,
gateware, client behavior -- the columns aggregate.py groups by) are left
untouched; only the "what did the pcap turn out to say" half is replaced. See
record_run.py's derive_fields() for exactly which fields that is.

    ./reprocess.py                                # every row with a .pcap
    ./reprocess.py --scenario ovctl_master_reload_nak1_sof0_240s
    ./reprocess.py --batch 20260904-tomasz-recheck
    ./reprocess.py --tag results/ovctl-20260904T112926Z   # a single run
    ./reprocess.py --dry-run                      # show what would change

A row without a `.pcap` on disk any more (cleaned up to save space) is
reported and skipped, not treated as an error.
"""

import argparse
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.realpath(__file__))
REFRAME = os.path.join(HERE, "reframe.py")

sys.path.insert(0, HERE)
from record_run import derive_fields, load_reframe_json  # noqa: E402


def load_manifest(path):
    rows = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--manifest", default=os.path.join(HERE, "results/manifest.jsonl"))
    ap.add_argument("--scenario")
    ap.add_argument("--batch")
    ap.add_argument("--tag", help="reprocess a single run by its tag path")
    ap.add_argument("--dump-blips", default=os.path.join(HERE, "results/blips"))
    ap.add_argument("--blip-window", type=int, default=256)
    ap.add_argument("--context-frames", type=int, default=8,
                    help="passed through to reframe.py -- raise it (with "
                         "--blip-window) so the SOF-gap check has a SOF within "
                         "range on both sides of a blip")
    ap.add_argument("--dry-run", action="store_true",
                    help="print what would change without touching anything")
    args = ap.parse_args()

    rows = load_manifest(args.manifest)
    targets = rows
    if args.scenario:
        targets = [r for r in targets if r["scenario"] == args.scenario]
    if args.batch:
        targets = [r for r in targets if r["batch"] == args.batch]
    if args.tag:
        targets = [r for r in targets if r["tag"] == args.tag]
    if not targets:
        sys.exit("no manifest rows match the given filters")

    print("reprocessing %d run(s) with the current reframe.py ..." % len(targets))
    changed = missing = 0
    updates_by_tag = {}    # tag -> derived-fields dict, for the merge-safe write below
    for r in targets:
        pcap = r["tag"] + ".pcap"
        if not os.path.exists(pcap):
            print("  MISSING pcap, skipped: %s" % pcap)
            missing += 1
            continue

        reframe_json = r["tag"] + ".reframe.json"
        verdict_txt = r["tag"] + ".verdict.txt"
        cmd = [sys.executable, REFRAME, pcap,
               "--dump-blips", args.dump_blips, "--blip-window", str(args.blip_window),
               "--context-frames", str(args.context_frames),
               "--json-summary", reframe_json]
        if args.dry_run:
            print("  would run: %s" % " ".join(cmd))
            continue

        with open(verdict_txt, "w") as f:
            p = subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT)
        reframe = load_reframe_json(reframe_json)
        new_fields = derive_fields(reframe)
        updates_by_tag[r["tag"]] = new_fields

        before = {k: r.get(k) for k in new_fields}
        if before != new_fields:
            changed += 1
            print("  %s  scenario=%s  outer=%s->%s inner=%s->%s"
                  % (r["ts"], r["scenario"], before["outer_verdict"],
                     new_fields["outer_verdict"], before["inner_verdict"],
                     new_fields["inner_verdict"]))
        del p

    if args.dry_run:
        print("\n(dry run -- nothing written)")
        return 0

    # Re-read the manifest fresh, right before writing, and merge our updates
    # onto THAT -- not onto the snapshot `rows` we started from -- so a
    # concurrent capture (a batch still appending new rows the whole time
    # this ran) can't have those new rows silently clobbered by this rewrite.
    # Every row not in updates_by_tag passes through completely untouched.
    # Still best avoided while a batch is actively running if you have the
    # choice -- this makes it safe, not free of the extra I/O.
    fresh_rows = load_manifest(args.manifest)
    for r in fresh_rows:
        upd = updates_by_tag.get(r["tag"])
        if upd is not None:
            r.update(upd)
    tmp = args.manifest + ".tmp"
    with open(tmp, "w") as f:
        for r in fresh_rows:
            f.write(json.dumps(r) + "\n")
    os.replace(tmp, args.manifest)

    print("\n%d run(s) reprocessed, %d changed verdict/fields, %d missing pcap"
          % (len(targets) - missing, changed, missing))
    if len(fresh_rows) != len(rows):
        print("(manifest grew from %d to %d rows while this ran -- those new "
              "rows were preserved, untouched)" % (len(rows), len(fresh_rows)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
