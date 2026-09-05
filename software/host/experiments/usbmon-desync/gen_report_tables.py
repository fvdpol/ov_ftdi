#!/usr/bin/env python3
"""Regenerate the data tables in issue25-report.md from the manifests, so the
report stays a living document as more runs land.

Emits two markdown tables between HTML-comment markers:

  <!-- BEGIN scenario-table -->  ... <!-- END scenario-table -->
      per (gateware x condition) hit rate -- from results/manifest.jsonl
  <!-- BEGIN event-table -->     ... <!-- END event-table -->
      one row per individual desync event -- from results/manifest.jsonl
      (offsets/skip/PIDs), results/sof_continuity.json (preR/postR), and the
      <tag>.reframe.json blip records (SOF gap).

    ./gen_report_tables.py                       # print both tables
    ./gen_report_tables.py --update issue25-report.md   # splice into the file
"""
import argparse
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.realpath(__file__))


def load_jsonl(path):
    with open(path) as f:
        return [json.loads(x) for x in f if x.strip()]


def gw_of(scenario):
    for g in ("bundled", "master", "tmon-filternak"):
        if g in scenario:
            return g
    return "?"


def cond_of(scenario):
    if "_reload_" in scenario:
        base = "reload"
    elif "_noload_" in scenario:
        base = "no-load"
    else:
        base = "?"
    if scenario.endswith("_drain1"):
        base += " + drain-wait"
    return base


def scenario_table(rows):
    # (gw, cond) -> [n, desync]
    agg = {}
    for r in rows:
        sc = r.get("scenario", "")
        if "nak1" not in sc:
            continue
        key = (gw_of(sc), cond_of(sc))
        a = agg.setdefault(key, [0, 0])
        a[0] += 1
        if r.get("inner_verdict") not in (None, "CLEAN"):
            a[1] += 1
    order = {"reload": 0, "no-load": 1, "no-load + drain-wait": 2}
    lines = ["| gateware | condition | runs | desync | rate |",
             "|---|---|--:|--:|--:|"]
    for (gw, cond) in sorted(agg, key=lambda k: (order.get(k[1], 9), k[0])):
        n, d = agg[(gw, cond)]
        lines.append("| %s | %s | %d | %d | %s |"
                     % (gw, cond, n, d, "%.0f%%" % (100 * d / n) if n else "-"))
    # totals per condition
    tot = {}
    for (gw, cond), (n, d) in agg.items():
        t = tot.setdefault(cond, [0, 0])
        t[0] += n
        t[1] += d
    lines.append("| | | | | |")
    for cond in sorted(tot, key=lambda c: order.get(c, 9)):
        n, d = tot[cond]
        lines.append("| **all** | **%s** | **%d** | **%d** | **%s** |"
                     % (cond, n, d, "%.0f%%" % (100 * d / n) if n else "-"))
    return "\n".join(lines)


def event_table(ana_rows, sof_list):
    sof = {os.path.basename(s.get("pcap", "")).replace(".pcap", ""): s
           for s in sof_list}
    lines = ["| run | gw | byte offset | % of stream | skip B | SOF gap (ms) | "
             "pre->post PID | preR | postR |",
             "|---|---|--:|--:|--:|--:|---|--:|--:|"]
    drows = [r for r in ana_rows if r.get("inner_verdict") not in (None, "CLEAN")]
    for r in sorted(drows, key=lambda r: r.get("inner_first_offset") or 0):
        tag = os.path.basename(r["tag"])
        gw = gw_of(r.get("scenario", ""))
        off = r.get("inner_first_offset")
        pct = r.get("inner_first_offset_pct")
        rj = r["tag"] + ".reframe.json"
        skip = sofgap = pre_pid = post_pid = None
        if os.path.exists(rj):
            try:
                ev = (json.load(open(rj)).get("inner") or {}).get("events") or []
                if ev:
                    e = ev[0]
                    skip = e.get("unmatched")           # bytes skipped to re-lock
                    sofgap = e.get("sof_frame_gap")     # frame-number units == ms (1ms/tick)
                    pre_pid = e.get("last_pre_pid")
                    post_pid = e.get("first_post_pid")
            except Exception:
                pass
        s = sof.get(tag, {})
        preR = s.get("pre_ratio")
        postR = s.get("post_ratio")
        lines.append("| %s | %s | %s | %s | %s | %s | %s | %s | %s |" % (
            tag.replace("ovctl-", ""), gw,
            "{:,}".format(off) if off else "?",
            ("%.1f%%" % pct) if pct is not None else "?",
            skip if skip is not None else "?",
            sofgap if sofgap is not None else "?",
            "%s -> %s" % (pre_pid or "?", post_pid or "?"),
            ("%.2f" % preR) if preR else "?",
            ("%.2f" % postR) if postR else "?"))
    return "\n".join(lines)


def splice(text, name, table):
    b, e = "<!-- BEGIN %s -->" % name, "<!-- END %s -->" % name
    pat = re.compile(re.escape(b) + r".*?" + re.escape(e), re.S)
    repl = "%s\n%s\n%s" % (b, table, e)
    if not pat.search(text):
        sys.exit("marker pair for %r not found in target" % name)
    return pat.sub(lambda _m: repl, text)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--manifest", default=os.path.join(HERE, "results/manifest.jsonl"))
    ap.add_argument("--analysis-manifest",
                    default=os.path.join(HERE, "results/manifest.analysis.jsonl"))
    ap.add_argument("--sof-json", default=os.path.join(HERE, "results/sof_continuity.json"))
    ap.add_argument("--update", metavar="FILE",
                    help="splice both tables into FILE between their markers")
    args = ap.parse_args()

    st = scenario_table(load_jsonl(args.manifest))
    ana = load_jsonl(args.analysis_manifest) if os.path.exists(args.analysis_manifest) else []
    sofl = json.load(open(args.sof_json)) if os.path.exists(args.sof_json) else []
    et = event_table(ana, sofl)

    if args.update:
        txt = open(args.update).read()
        txt = splice(txt, "scenario-table", st)
        txt = splice(txt, "event-table", et)
        open(args.update, "w").write(txt)
        print("updated %s" % args.update)
    else:
        print("<!-- BEGIN scenario-table -->\n%s\n<!-- END scenario-table -->\n" % st)
        print("<!-- BEGIN event-table -->\n%s\n<!-- END event-table -->" % et)


if __name__ == "__main__":
    main()
