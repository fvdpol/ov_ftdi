#!/usr/bin/env python3
"""Verify PlanAhead SSN-analysis results meet a minimum noise margin.

This script parses `report_ssn` CSV output and checks that every pin the
tool was able to analyze has a Remaining Margin >= --min-margin percent.
"""

import argparse
import csv
import sys


def parse_report(text):
    """Parse a report_ssn CSV report into a list of row dicts.

    Leading '#' comment lines (version, part, VCCAUX, timestamp) are
    dropped; the remaining CSV header/rows are parsed with csv.DictReader.
    Column names are stripped since report_ssn pads some headers with a
    leading space (e.g. " Notes").
    """
    lines = [line for line in text.splitlines() if not line.startswith("#")]
    reader = csv.DictReader(lines)
    return [{(k.strip() if k else k): v for k, v in row.items()} for row in reader]


def check_report(report, min_margin):
    """Parse a report_ssn CSV report and verify every analyzed pin meets min_margin.

    Prints one line per analyzed pin plus an error line per violation.

    Exit codes:
      0 if all analyzed pins meet the margin
      1 if any pin is below the margin
      2 if the report is unreadable/empty.
    """
    try:
        with open(report) as f:
            text = f.read()
    except OSError as e:
        print("ERROR: cannot read SSN report %s: %s" % (report, e),
              file=sys.stderr)
        return 2

    rows = parse_report(text)
    if not rows:
        print("ERROR: no SSN results found in %s "
              "(did report_ssn run, and does the design have output pins?)"
              % report, file=sys.stderr)
        return 2

    print("SSN check of %s (require remaining margin >= %.1f%%):"
          % (report, min_margin))

    violations = 0
    checked = 0
    for row in rows:
        name = row.get("Signal Name", "?")
        pin = row.get("Pin Number", "?")
        margin_str = (row.get("Remaining Margin (%)") or "").strip()
        notes = (row.get("Notes") or "").strip()

        if not margin_str:
            print("  SKIP            %s (%s)  (%s)" % (name, pin, notes or "not analyzed"))
            continue

        checked += 1
        margin = float(margin_str)
        failed = margin < min_margin
        print("  %s %+8.1f%%  %s (%s)"
              % ("FAIL" if failed else "OK  ", margin, name, pin))

        if failed:
            violations += 1
            print("    ERROR: remaining margin %.1f%% < required %.1f%% for %s (%s)"
                  % (margin, min_margin, name, pin), file=sys.stderr)

    print("\n%d pin(s) checked, %d violation(s)." % (checked, violations))
    if violations:
        print("ERROR: SSN analysis found pin(s) below the %.1f%% margin."
              % min_margin, file=sys.stderr)
        return 1
    print("All analyzed pins meet the %.1f%% remaining margin." % min_margin)
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("report", help="report_ssn CSV report")
    ap.add_argument("--min-margin", type=float, default=0.0,
                    help="minimum required remaining margin in percent (default: 0.0)")
    args = ap.parse_args()
    return check_report(args.report, args.min_margin)


if __name__ == "__main__":
    sys.exit(main())
