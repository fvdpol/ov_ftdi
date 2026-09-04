#!/usr/bin/env python3
"""Append one run's result to results/manifest.jsonl.

Called by run_bisect.sh at the end of every run. Takes everything as argv
(not shell-interpolated JSON) since some fields -- gateware-bitstream in
particular -- are free-text device output that could otherwise break a
heredoc. The manifest is append-only *for capture-time facts*: re-running the
same scenario later, in a new batch, just adds more rows.

The per-row fields split into two groups:
  - capture-time facts (scenario, gateware, client behavior, ...) -- set once,
    from the actual hardware run, never touched again.
  - derived facts (verdict, event offsets, wallclock, loss-vs-insertion hint,
    ...) -- everything reframe.py computes from the stored .pcap. These can
    be recomputed at any time, from the same .pcap, with improved heuristics
    -- see reprocess.py, which re-runs reframe.py against already-captured
    pcaps and replaces only this half of each row. No hardware, no rig time.
"""

import argparse
import json
import sys


def derive_fields(reframe):
    """Everything computable from a reframe.py --json-summary dict alone --
    the half of a manifest row that reprocess.py is allowed to replace."""
    outer, inner = reframe["outer"], reframe["inner"]
    return {
        "outer_verdict": outer["verdict"],
        "inner_verdict": inner["verdict"],
        "inner_unmatched": inner.get("unmatched", 0),
        # Exact byte offset the framer tripped on, in the inner (whacker)
        # stream and mapped back to the outer (wire) stream, plus how far
        # into the capture that is as %% of that run's total inner-stream
        # bytes -- lets aggregate.py show whether events cluster late (per
        # Frank's 2026-09-04 observation: the 2 known events were at 59%/69%
        # into their 60s runs, not near start). wallclock is the usbmon
        # (kernel) completion time of the URB carrying that byte -- host
        # wall-clock, not a device-side timestamp; the blip dump under
        # results/blips/ has the full pre/post frame context either way.
        "inner_first_offset": inner.get("first_offset"),
        "inner_first_offset_outer": inner.get("first_offset_outer_offset"),
        "inner_first_offset_pct": inner.get("first_offset_pct"),
        "inner_first_wallclock": inner.get("wallclock"),
        # A pcap can hold more than one desync event, especially at the
        # longer (240s) run lengths -- see reframe.py's per-event blip dumps
        # under results/blips/ for all of them, not just the first.
        "inner_num_events": inner.get("num_events", 0),
        "outer_num_events": outer.get("num_events", 0),
        # loss-vs-insertion hint for the first inner event: True means the
        # skipped bytes are a literal repeat of what preceded them (points at
        # a stale re-read/duplicate rather than data going missing).
        "inner_first_dup_of_preceding":
            (inner.get("events") or [{}])[0].get("dup_of_preceding"),
    }


def load_reframe_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        return {"outer": {"verdict": "NO_PCAP"}, "inner": {"verdict": "NO_PCAP"}}


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
    ap.add_argument("--client-overflow-events", type=int, default=-1,
                    help="OVF_INSERT_NUM_OVF for this session; -1 = not reported "
                         "(older client, or client crashed before teardown)")
    ap.add_argument("--client-overflow-total", type=int, default=-1,
                    help="OVF_INSERT_NUM_TOTAL for this session (the denominator "
                         "the overflow count is out of); -1 = not reported")
    ap.add_argument("--reframe-json", required=True)
    args = ap.parse_args()

    reframe = load_reframe_json(args.reframe_json)

    rec = {
        # --- capture-time facts: set once, from the hardware run ---
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
        "client_desynced": args.client_unmatched > 0,
        # RX-path overflow (OVF_INSERT_NUM_OVF/_TOTAL), relevant once the
        # matrix includes no-`--filter-nak` scenarios (dense, overflow-prone
        # by design). -1 from run_bisect.sh means "not reported" -> None,
        # distinct from a genuine 0 events.
        "client_overflow_events": (args.client_overflow_events
                                   if args.client_overflow_events >= 0 else None),
        "client_overflow_total": (args.client_overflow_total
                                  if args.client_overflow_total >= 0 else None),
    }
    # --- derived facts: reframe.py's read of the stored pcap; reprocess.py
    # is the supported way to replace these later without re-running hardware.
    rec.update(derive_fields(reframe))

    with open(args.manifest, "a") as f:
        f.write(json.dumps(rec) + "\n")
    print("manifest: %s  (scenario=%s)" % (args.manifest, rec["scenario"]))


if __name__ == "__main__":
    sys.exit(main())
