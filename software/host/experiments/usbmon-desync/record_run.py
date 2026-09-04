#!/usr/bin/env python3
"""Append one run's result to results/manifest.jsonl.

Called by run_bisect.sh at the end of every run. Takes everything as argv
(not shell-interpolated JSON) since some fields -- gateware-bitstream in
particular -- are free-text device output that could otherwise break a
heredoc. The manifest is append-only: re-running the same scenario later,
in a new batch, just adds more rows -- see aggregate.py to sum it.
"""

import argparse
import json
import sys


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--ts", required=True)
    ap.add_argument("--scenario", required=True)
    ap.add_argument("--batch", default="")
    ap.add_argument("--gateware-tag", required=True)
    ap.add_argument("--gateware-bitstream", default="")
    ap.add_argument("--reload", required=True, choices=["reload", "noload"])
    ap.add_argument("--filter-nak", required=True)
    ap.add_argument("--filter-sof", required=True)
    ap.add_argument("--mode", required=True)
    ap.add_argument("--secs", required=True, type=float)
    ap.add_argument("--tag", required=True)
    ap.add_argument("--client-rc", required=True, type=int)
    ap.add_argument("--client-unmatched", required=True, type=int)
    ap.add_argument("--client-assert", required=True, type=int)
    ap.add_argument("--reframe-json", required=True)
    args = ap.parse_args()

    try:
        with open(args.reframe_json) as f:
            reframe = json.load(f)
    except FileNotFoundError:
        reframe = {"outer": {"verdict": "NO_PCAP"}, "inner": {"verdict": "NO_PCAP"}}

    rec = {
        "ts": args.ts,
        "scenario": args.scenario,
        "batch": args.batch or None,
        "gateware_tag": args.gateware_tag,
        "gateware_bitstream": args.gateware_bitstream.strip() or None,
        "reload": args.reload == "reload",
        "filter_nak": args.filter_nak == "1",
        "filter_sof": args.filter_sof == "1",
        "mode": args.mode,
        "secs": args.secs,
        "tag": args.tag,
        "client_rc": args.client_rc,
        "client_unmatched": args.client_unmatched,
        "client_assert": args.client_assert,
        "outer_verdict": reframe["outer"]["verdict"],
        "inner_verdict": reframe["inner"]["verdict"],
        "inner_unmatched": reframe["inner"].get("unmatched", 0),
        # how far into the capture the first inner-layer stray byte landed, as
        # % of that run's total inner-stream bytes -- lets aggregate.py show
        # whether events cluster late (per Frank's 2026-09-04 observation: the
        # 2 known events were at 59%/69% into their 60s runs, not near start).
        "inner_first_offset_pct": reframe["inner"].get("first_offset_pct"),
        "client_desynced": args.client_unmatched > 0,
    }
    with open(args.manifest, "a") as f:
        f.write(json.dumps(rec) + "\n")
    print("manifest: %s  (scenario=%s)" % (args.manifest, rec["scenario"]))


if __name__ == "__main__":
    sys.exit(main())
