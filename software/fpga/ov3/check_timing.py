#!/usr/bin/env python3
"""Verify ISE timing-analysis results meet a minimum slack margin.

This script parses `trce` text report (.twr file) and checks that every timing
constraint with analyzed paths has a worst-case slack >= --min-slack ns.
"""

import argparse
import re
import sys

# Each constraint section in a trce report starts with a line beginning here.
_CONSTRAINT_ANCHOR = re.compile(r'^Timing constraint:', re.M)
# The full constraint statement, which may wrap across several lines, ends at
# the first ";".
_DESC_RE = re.compile(r'Timing constraint:\s*(.+?;)', re.S)
# Each constraint reports one or more slacks of different kinds (setup,
# min/max period limit, pulse width), e.g. "Slack:  1.234ns (requirement -
# ...)". May be negative, and trce sometimes omits the space before "ns". The
# worst (minimum) across a block is the constraint's worst-case slack.
_SLACK_RE = re.compile(r'Slack:\s*(-?[0-9.]+)\s*ns')
# PERIOD fallback when a block reports no explicit Slack line.
_MINPERIOD_RE = re.compile(r'Minimum period is\s+([0-9.]+)\s*ns')
_PERIOD_REQ_RE = re.compile(r'PERIOD[^0-9]*([0-9.]+)\s*ns')
_PATHS_RE = re.compile(r'(\d+)\s+paths?\s+analyzed')
_ERRORS_RE = re.compile(r'(\d+)\s+timing errors?\s+detected')
# Trailing report sections (after the last constraint) that must not be folded
# into the last constraint block.
_TRAILERS = ("Data Sheet report:", "Timing summary:")


def parse_constraints(text):
    """Split the report into (description, body) blocks, one per constraint."""
    # Drop trailing summary/data-sheet sections so their contents can't be
    # attributed to the last constraint.
    cut = len(text)
    for marker in _TRAILERS:
        i = text.find(marker)
        if i != -1:
            cut = min(cut, i)
    text = text[:cut]

    anchors = list(_CONSTRAINT_ANCHOR.finditer(text))
    blocks = []
    for i, m in enumerate(anchors):
        end = anchors[i + 1].start() if i + 1 < len(anchors) else len(text)
        body = text[m.start():end]
        dm = _DESC_RE.search(body)
        desc = re.sub(r'\s+', ' ', dm.group(1)).strip() if dm \
            else body.splitlines()[0].split(":", 1)[-1].strip()
        blocks.append((desc, body))
    return blocks


def worst_slack(desc, body):
    """Worst-case slack (ns) for a constraint block.

    Returns (slack, note). slack is None when no value applies (constraint with
    no analyzed paths, or no slack reported), with the reason in note.
    """
    slacks = [float(s) for s in _SLACK_RE.findall(body)]
    if slacks:
        return min(slacks), None

    # PERIOD constraints may report only "Minimum period is X ns".
    mp = _MINPERIOD_RE.search(body)
    req = _PERIOD_REQ_RE.search(desc)
    if mp and req:
        return float(req.group(1)) - float(mp.group(1)), "from minimum period"

    paths = _PATHS_RE.search(body)
    if paths and paths.group(1) == "0":
        return None, "no paths analyzed"
    return None, "no slack reported"


def check_report(report, min_slack):
    """Parse a trce .twr report and verify every constraint meets min_slack.

    Prints one line per constraint plus an error line per violation.

    Exit codes:
      0 if all checked constraints pass
      1 if any is below the margin or has timing errors
      2 if the report is unreadable/empty.
    """
    try:
        with open(report) as f:
            text = f.read()
    except OSError as e:
        print("ERROR: cannot read timing report %s: %s" % (report, e),
              file=sys.stderr)
        return 2

    blocks = parse_constraints(text)
    if not blocks:
        print("ERROR: no timing constraints found in %s "
              "(did trce run, and are there constraints?)" % report,
              file=sys.stderr)
        return 2

    print("Timing check of %s (require slack >= %.3f ns):"
          % (report, min_slack))

    violations = 0
    checked = 0
    for desc, body in blocks:
        slack, note = worst_slack(desc, body)
        m = _ERRORS_RE.search(body)
        n_err = int(m.group(1)) if m else 0

        if slack is None and n_err == 0:
            print("  SKIP            %s  (%s)" % (desc, note))
            continue

        checked += 1
        failed = n_err > 0 or (slack is not None and slack < min_slack)
        slack_str = "%+7.3f ns" % slack if slack is not None else "    n/a"
        print("  %s %s  %s" % ("FAIL" if failed else "OK  ", slack_str, desc))

        if failed:
            violations += 1
            if n_err:
                print("    ERROR: %d timing error(s) detected for: %s"
                      % (n_err, desc), file=sys.stderr)
            if slack is not None and slack < min_slack:
                print("    ERROR: slack %.3f ns < required %.3f ns for: %s"
                      % (slack, min_slack, desc), file=sys.stderr)

    print("\n%d constraint(s) checked, %d violation(s)." % (checked, violations))
    if violations:
        print("ERROR: timing constraints not met with >= %.3f ns slack."
              % min_slack, file=sys.stderr)
        return 1
    print("All checked constraints meet the %.3f ns slack margin." % min_slack)
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("report", help="trce text report (.twr)")
    ap.add_argument("--min-slack", type=float, default=0.3,
                    help="minimum required slack in ns")
    args = ap.parse_args()
    return check_report(args.report, args.min_slack)


if __name__ == "__main__":
    sys.exit(main())
