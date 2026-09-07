"""Enforce separate line and branch coverage thresholds."""

import argparse
import json
import sys
from pathlib import Path


THRESHOLD = 80.0


def percentage(covered: int, total: int) -> float:
    return 100.0 if total == 0 else covered / total * 100


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path, help="Path to a coverage.py JSON report")
    args = parser.parse_args()

    totals = json.loads(args.report.read_text())["totals"]
    line_coverage = percentage(totals["covered_lines"], totals["num_statements"])
    branch_coverage = percentage(totals["covered_branches"], totals["num_branches"])
    print(f"Line coverage: {line_coverage:.2f}% (required: {THRESHOLD:.2f}%)")
    print(f"Branch coverage: {branch_coverage:.2f}% (required: {THRESHOLD:.2f}%)")

    return int(line_coverage < THRESHOLD or branch_coverage < THRESHOLD)


if __name__ == "__main__":
    sys.exit(main())
