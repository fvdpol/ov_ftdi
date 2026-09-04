#!/usr/bin/env python3
"""Aggregate results/manifest.jsonl into per-scenario hit rates.

The manifest is append-only across every batch that has ever been run (see
run_bisect.sh / record_run.py), so running this after adding more samples to
an existing scenario just widens that scenario's N -- nothing needs to be
merged or re-run by hand.

    ./aggregate.py                          # all scenarios, all batches
    ./aggregate.py --scenario master_reload_nak1_sof0
    ./aggregate.py --batch 20260905-tomasz-recheck
    ./aggregate.py --since 20260905T000000Z
    ./aggregate.py --list-batches
"""

import argparse
import collections
import json
import sys


def load(manifest, count_mode=False):
    """count_mode: a missing manifest means "0 runs so far" (a resuming
    orchestrator's very first call, before anything has ever completed) --
    not an error. Otherwise it's a friendly exit, for a human running this
    directly."""
    rows = []
    try:
        with open(manifest) as f:
            for line in f:
                line = line.strip()
                if line:
                    rows.append(json.loads(line))
    except FileNotFoundError:
        if count_mode:
            return rows
        sys.exit("no manifest at %s yet -- run run_bisect.sh at least once" % manifest)
    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--manifest", default="results/manifest.jsonl")
    ap.add_argument("--scenario", help="only this scenario")
    ap.add_argument("--batch", help="only this batch label")
    ap.add_argument("--since", help="only runs with ts >= this (lexical, e.g. 20260905T000000Z)")
    ap.add_argument("--list-batches", action="store_true",
                    help="list distinct batch labels seen and exit")
    ap.add_argument("--count", action="store_true",
                    help="print just the number of matching rows (bare integer, "
                         "nothing else) and exit -- e.g. for an orchestrator to "
                         "resume a scenario after N-already-done, rather than "
                         "restarting an interrupted experiment from scratch")
    ap.add_argument("--min-traffic-bps", type=float, default=50000,
                    help="flag runs below this reframed_bytes/secs rate as "
                         "suspiciously quiet (default 50000 -- see run_bisect.sh's "
                         "own live check, which uses the same default)")
    args = ap.parse_args()

    rows = load(args.manifest, count_mode=args.count)

    if args.list_batches:
        batches = sorted({r["batch"] or "(none)" for r in rows})
        for b in batches:
            n = sum(1 for r in rows if (r["batch"] or "(none)") == b)
            print("%-30s %d runs" % (b, n))
        return 0

    if args.scenario:
        rows = [r for r in rows if r["scenario"] == args.scenario]
    if args.batch:
        rows = [r for r in rows if r["batch"] == args.batch]
    if args.since:
        rows = [r for r in rows if r["ts"] >= args.since]

    if args.count:
        print(len(rows))
        return 0

    if not rows:
        print("no runs match the given filters")
        return 0

    by_scenario = collections.defaultdict(list)
    for r in rows:
        by_scenario[r["scenario"]].append(r)

    print("%-34s %5s %8s %8s %10s %10s %8s %8s" %
          ("scenario", "N", "desync", "rate", "inner_blip", "outer_bad",
           "ovf_csr", "ovf_pcap"))
    total_n = total_desync = 0
    overflow_detail = []   # (scenario, source, sum, max) for the footer
    for scenario in sorted(by_scenario):
        rs = by_scenario[scenario]
        n = len(rs)
        desync = sum(1 for r in rs if r["client_desynced"])
        inner_blip = sum(1 for r in rs
                          if r["inner_verdict"] in ("RECOVERED", "NEVER_RECOVERED"))
        outer_bad = sum(1 for r in rs
                         if r["outer_verdict"] in ("RECOVERED", "NEVER_RECOVERED"))
        # Two independent overflow sources, deliberately not merged into one
        # column -- they measure different things (see aggregate --help /
        # record_run.py) and can legitimately disagree:
        #   ovf_csr  = client_overflow_events, the CSR hardware counter
        #              (RX-path words dropped at ovf_insert.py); capture-time
        #              only, absent for runs before that was added.
        #   ovf_pcap = inner_overflow_packets, HF0_OVF decoded from the wire
        #              bytes themselves (packets flagged downstream); works
        #              for ANY captured pcap, old or new -- reprocess.py
        #              backfills it for runs that predate ovf_csr entirely.
        # -1/absent in either is "not measured", not zero.
        for key, label in (("client_overflow_events", "csr"),
                            ("inner_overflow_packets", "pcap")):
            vals = [r.get(key) for r in rs if r.get(key) is not None]
            runs_with = sum(1 for v in vals if v > 0)
            col = "%d/%d" % (runs_with, len(vals)) if vals else "n/a"
            if label == "csr":
                ovf_csr_col = col
            else:
                ovf_pcap_col = col
            if runs_with:
                overflow_detail.append((scenario, label, sum(vals), max(vals)))
        total_n += n
        total_desync += desync
        print("%-34s %5d %8d %7.0f%% %10d %10d %8s %8s" %
              (scenario, n, desync, 100.0 * desync / n, inner_blip, outer_bad,
               ovf_csr_col, ovf_pcap_col))
    print("-" * 97)
    print("%-34s %5d %8d %7.0f%%" %
          ("TOTAL", total_n, total_desync,
           100.0 * total_desync / total_n if total_n else 0))
    print("(ovf_csr/ovf_pcap: runs with >0 overflow / runs where that source was "
          "measured at all; 'n/a' = never measured that way for this scenario)")

    if overflow_detail:
        print("\nscenarios with overflow events -- sum and max, by source:")
        for scenario, label, total, mx in overflow_detail:
            print("  %-34s %-4s sum=%-10d max=%d" % (scenario, label, total, mx))

    # Real-vs-inflated check for HF0_OVF (2026-09-05, Frank): does an SOF
    # frame-number gap actually confirm missing traffic around these events,
    # or does the overflow rate look inflated relative to what the wire
    # shows? gt1 = real evidence of a missing microframe; le1 = none found
    # (not proof nothing was lost -- SOF-gap is whole-microframe granularity
    # -- just no macroscopic signature); unresolved = ran out of stream
    # before a following SOF. quartiles: even spread across a run argues for
    # a steady per-burst limit; back-loaded argues for something filling up
    # over time (Frank's original working assumption for when overflow
    # should appear at all).
    ovf_sof = [r for r in rows if r.get("inner_overflow_packets")]
    if ovf_sof:
        print("\nHF0_OVF events -- SOF-gap real-vs-inflated check, and when in the run "
              "they land (quartile 1..4):")
        for r in ovf_sof:
            q = r.get("inner_overflow_quartile_counts") or [0, 0, 0, 0]
            print("  %-34s gt1=%-4s le1=%-6s unresolved=%-4s max_gap=%-4s "
                  "quartiles=%s  tag=%s"
                  % (r["scenario"], r.get("inner_overflow_sof_gap_gt1"),
                     r.get("inner_overflow_sof_gap_le1"),
                     r.get("inner_overflow_sof_gap_unresolved"),
                     r.get("inner_overflow_sof_gap_max"), q, r["tag"]))

    # 2026-09-04 postmortem: 56/64 runs in one batch quietly captured USB
    # background chatter instead of real DUT traffic after the DUT dropped
    # off mid-batch -- every other check in this report (desync rate,
    # overflow, blips) stayed "clean" because there was nothing to desync
    # on. run_bisect.sh now fails a run live (exit 3) below this same
    # threshold, but flag it here too for anything captured before that, or
    # with MIN_TRAFFIC_BPS overridden away at capture time.
    quiet = [r for r in rows if r.get("reframed_bytes") is not None and r.get("secs")
             and r["reframed_bytes"] / r["secs"] < args.min_traffic_bps]
    if quiet:
        print("\n%d run(s) captured suspiciously little traffic (< %.0f B/s) -- "
              "likely a dead/disconnected DUT, NOT evidence of a clean run. "
              "Treat these as invalid, not as \"no desync happened\":"
              % (len(quiet), args.min_traffic_bps))
        for r in quiet:
            print("  %8.0f B/s  (%d bytes / %ss)  scenario=%s  tag=%s"
                  % (r["reframed_bytes"] / r["secs"], r["reframed_bytes"], r["secs"],
                     r["scenario"], r["tag"]))

    batches = sorted({r["batch"] or "(none)" for r in rows})
    if len(batches) > 1:
        print("\n(spans %d batches: %s)" % (len(batches), ", ".join(batches)))

    never = [r for r in rows if r["inner_verdict"] == "NEVER_RECOVERED"
             or r["outer_verdict"] == "NEVER_RECOVERED"]
    if never:
        print("\n%d run(s) had a NEVER_RECOVERED wire-layer desync (not just a "
              "self-healing blip) -- worth a second look:" % len(never))
        for r in never:
            print("  %s  scenario=%s  tag=%s" % (r["ts"], r["scenario"], r["tag"]))

    blips = [r for r in rows if r.get("inner_first_offset_pct") is not None]
    if blips:
        import datetime
        print("\ninner-layer event onset -- exact byte, %% into the capture, "
              "and usbmon wall-clock (2026-09-04: is this late-onset, or "
              "does duration not matter?). Full pre/post frame context for "
              "each is in results/blips/:")
        for r in sorted(blips, key=lambda r: r["inner_first_offset_pct"]):
            wc = r.get("inner_first_wallclock")
            wc_str = (datetime.datetime.fromtimestamp(wc).isoformat(timespec="seconds")
                      if wc is not None else "unknown")
            sof_gap = r.get("inner_first_sof_frame_gap")
            print("  %5.1f%%  byte %-10s wallclock %s  SOF-gap=%-4s  scenario=%s  tag=%s"
                  % (r["inner_first_offset_pct"], r.get("inner_first_offset"),
                     wc_str, sof_gap if sof_gap is not None else "?",
                     r["scenario"], r["tag"]))

    # SOF-gap > 1 is the strongest signal this harness computes for real
    # traffic having gone missing (an actual USB sequence number, not a
    # heuristic) -- and an invalid post-relock PID means the "recovery"
    # itself may be a coincidental false-positive, not a genuine boundary.
    loss_evidence = [r for r in rows if (r.get("inner_first_sof_frame_gap") or 0) > 1]
    bad_relock = [r for r in rows if r.get("inner_first_post_pid_valid") is False]
    if loss_evidence:
        print("\n%d run(s) with a SOF frame-number gap >1 across the first inner "
              "event -- real traffic (not just bytes) looks to have gone "
              "missing there:" % len(loss_evidence))
        for r in loss_evidence:
            print("  gap=%-4s  scenario=%s  tag=%s"
                  % (r["inner_first_sof_frame_gap"], r["scenario"], r["tag"]))
    if bad_relock:
        print("\n%d run(s) where the byte right after re-lock is NOT a "
              "structurally valid USB PID -- the 'recovery' may be a "
              "coincidental false-positive, not a genuine packet boundary:"
              % len(bad_relock))
        for r in bad_relock:
            print("  scenario=%s  tag=%s" % (r["scenario"], r["tag"]))

    return 0


if __name__ == "__main__":
    sys.exit(main())
