"""Summarizes a runs.tsv that tools/build-loop/measure wrote, as a Markdown table.

Usage: python3 tools/build-loop/summarize.py OUT_DIR/runs.tsv
"""

import csv
import statistics
import sys


def span(values):
    low, high = min(values), max(values)
    return str(low) if low == high else f"{low} to {high}"


def main(path):
    with open(path) as f:
        lines = [line for line in f if not line.startswith("#")]
    rows = list(csv.DictReader(lines, delimiter="\t"))
    series = list(dict.fromkeys(row["series"] for row in rows))
    print("| Series | Runs | Median (s) | Range (s) | Failed runs | Crates compiled | sccache hits / misses per run |")
    print("|---|---|---|---|---|---|---|")
    for name in series:
        group = [row for row in rows if row["series"] == name]
        seconds = [float(row["seconds"]) for row in group]
        failed = sum(row["exit"] != "0" for row in group)
        compiled = [int(row["compiled"]) for row in group]
        if group[0]["sccache_hits"] == "-":
            cache = "not used"
        else:
            cache = ", ".join(f"{row['sccache_hits']} / {row['sccache_misses']}" for row in group)
        print(
            f"| {name} | {len(group)} | {statistics.median(seconds):.1f} "
            f"| {min(seconds):.1f} to {max(seconds):.1f} | {failed} | {span(compiled)} | {cache} |"
        )


if __name__ == "__main__":
    main(sys.argv[1])
