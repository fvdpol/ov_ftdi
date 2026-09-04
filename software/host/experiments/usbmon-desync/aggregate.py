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


def load(manifest):
    rows = []
    try:
        with open(manifest) as f:
            for line in f:
                line = line.strip()
                if line:
                    rows.append(json.loads(line))
    except FileNotFoundError:
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
    args = ap.parse_args()

    rows = load(args.manifest)

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

    if not rows:
        print("no runs match the given filters")
        return 0

    by_scenario = collections.defaultdict(list)
    for r in rows:
        by_scenario[r["scenario"]].append(r)

    print("%-34s %5s %8s %8s %10s %10s" %
          ("scenario", "N", "desync", "rate", "inner_blip", "outer_bad"))
    total_n = total_desync = 0
    for scenario in sorted(by_scenario):
        rs = by_scenario[scenario]
        n = len(rs)
        desync = sum(1 for r in rs if r["client_desynced"])
        inner_blip = sum(1 for r in rs
                          if r["inner_verdict"] in ("RECOVERED", "NEVER_RECOVERED"))
        outer_bad = sum(1 for r in rs
                         if r["outer_verdict"] in ("RECOVERED", "NEVER_RECOVERED"))
        total_n += n
        total_desync += desync
        print("%-34s %5d %8d %7.0f%% %10d %10d" %
              (scenario, n, desync, 100.0 * desync / n, inner_blip, outer_bad))
    print("-" * 80)
    print("%-34s %5d %8d %7.0f%%" %
          ("TOTAL", total_n, total_desync,
           100.0 * total_desync / total_n if total_n else 0))

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
            print("  %5.1f%%  byte %-10s wallclock %s  scenario=%s  tag=%s"
                  % (r["inner_first_offset_pct"], r.get("inner_first_offset"),
                     wc_str, r["scenario"], r["tag"]))

    return 0


if __name__ == "__main__":
    sys.exit(main())
