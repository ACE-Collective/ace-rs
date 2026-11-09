"""Summarizes what tools/memory/measure wrote (PLAN.md 3.5).

Usage: python3 tools/memory/summarize.py OUT_DIR [--series NAME] [--tsv FILE] [--tasks-tsv FILE]

Prints Markdown tables: for each figure, the median and range over the runs. A figure within one
run is itself a median or a peak over that run's samples, and its name says which. With --tsv or
--tasks-tsv it also appends the per-run figures and the per-task rows to those files, under the
series NAME (the default is OUT_DIR's name), writing a header when a file is new.
"""

import argparse
import csv
import json
import statistics
from pathlib import Path

PHASES = ["idle-before", "compare", "idle-after"]
ROWS = [("parsers", "supervisor"), ("lookups", "main"), ("ace", "main"), ("postgres", "main"), ("bucket", "main")]


def read_tsv(path):
    with open(path) as f:
        lines = [line.lstrip("# ") if i == 0 else line for i, line in enumerate(f)]
    return [row for row in csv.DictReader(lines, delimiter="\t") if not row[next(iter(row))].startswith("#")]


def mb(kb):
    return kb / 1024


def percentile(values, share):
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(len(ordered) * share))]


def one_run(run_dir):
    """A run's figures, {(phase, subject, metric): kB or a count}, and its per-task rows."""
    figures = {}
    meta = json.loads((run_dir / "meta.json").read_text())
    load = json.loads((run_dir / "load.json").read_text())
    samples = read_tsv(run_dir / "samples.tsv")
    for phase in PHASES:
        for service, role in ROWS:
            rows = [r for r in samples if r["phase"] == phase and r["service"] == service and r["role"] == role]
            for field in ("private", "private_dirty", "pss", "rss", "anon"):
                values = [int(r[f"{field}_kb"]) for r in rows]
                subject = f"{service} {role}"
                figures[(phase, subject, f"{field} median")] = statistics.median(values)
                figures[(phase, subject, f"{field} peak")] = max(values)
            figures[(phase, f"{service} {role}", "processes")] = max(int(r["procs"]) for r in rows)
        peak = meta["parsers_pool_peak_kb"][phase]
        figures[(phase, "parsers supervisor and tasks", "private peak")] = peak["private"]
        figures[(phase, "parsers supervisor and tasks", "private_dirty peak")] = peak["private_dirty"]
        figures[(phase, "parsers supervisor and tasks", "pss peak")] = peak["pss"]
        figures[(phase, "parsers tasks", "running at once")] = meta["parsers_concurrent_tasks"][phase]

    cgroup = read_tsv(run_dir / "cgroup.tsv")
    for phase in PHASES:
        for service in {r["service"] for r in cgroup}:
            rows = [r for r in cgroup if r["phase"] == phase and r["service"] == service]
            for field in ("anon", "file", "kernel", "current"):
                values = [int(r[f"{field}_kb"]) for r in rows]
                figures[(phase, f"{service} cgroup", f"{field} median")] = statistics.median(values)
                figures[(phase, f"{service} cgroup", f"{field} peak")] = max(values)
    for row in read_tsv(run_dir / "peaks.tsv"):
        subject = f"{row['service']} cgroup"
        figures[(row["phase"], subject, "memory.peak")] = int(row["peak_kb"])
        figures[(row["phase"], subject, "limit")] = int(row["limit"]) // 1024 if row["limit"] != "max" else 0
        for event in ("events_max", "events_oom", "events_oom_kill"):
            figures[(row["phase"], subject, event)] = int(row[event])

    sampled = {r["pid"]: r for r in read_tsv(run_dir / "tasks.tsv")}
    exits = read_tsv(run_dir / "taskstats.tsv")
    rows = []
    for record in exits:
        seen = sampled.get(record["pid"])
        rows.append(
            {
                "pid": record["pid"],
                "exit_code": record["exit_code"],
                "lifetime_ms": record["lifetime_ms"],
                "cpu_ms": record["cpu_ms"],
                "exit_peak_rss_kb": record["peak_rss_kb"],
                "samples": seen["samples"] if seen else "0",
                "private_kb": seen["private_kb"] if seen else "",
                "private_dirty_kb": seen["private_dirty_kb"] if seen else "",
                "pss_kb": seen["pss_kb"] if seen else "",
                "rss_kb": seen["rss_kb"] if seen else "",
                "anon_kb": seen["anon_kb"] if seen else "",
            }
        )
    with_samples = [r for r in rows if int(r["samples"]) > 0]
    task = "parsers task process"
    figures[("compare", task, "exit records")] = len(rows)
    figures[("compare", task, "sampled")] = len(with_samples)
    figures[("compare", task, "non-zero exits")] = sum(r["exit_code"] != "0" for r in rows)
    figures[("compare", task, "dropped exit records")] = sum(
        1 for line in (run_dir / "taskstats.tsv").read_text().splitlines() if line.startswith("# dropped")
    )
    lifetimes = [float(r["lifetime_ms"]) for r in rows]
    figures[("compare", task, "lifetime ms median")] = statistics.median(lifetimes)
    figures[("compare", task, "lifetime ms peak")] = max(lifetimes)
    figures[("compare", task, "cpu ms median")] = statistics.median(float(r["cpu_ms"]) for r in rows)
    figures[("compare", task, "cpu ms peak")] = max(float(r["cpu_ms"]) for r in rows)
    exit_rss = [int(r["exit_peak_rss_kb"]) for r in rows]
    figures[("compare", task, "exit peak rss median")] = statistics.median(exit_rss)
    figures[("compare", task, "exit peak rss p95")] = percentile(exit_rss, 0.95)
    figures[("compare", task, "exit peak rss peak")] = max(exit_rss)
    for field in ("private", "private_dirty", "pss", "anon"):
        values = [int(r[f"{field}_kb"]) for r in with_samples]
        figures[("compare", task, f"{field} median")] = statistics.median(values)
        figures[("compare", task, f"{field} p95")] = percentile(values, 0.95)
        figures[("compare", task, f"{field} peak")] = max(values)
    # how far sampling fell short of the peak the kernel recorded, on the one figure both have
    short = [int(r["exit_peak_rss_kb"]) - int(r["rss_kb"]) for r in with_samples]
    figures[("compare", task, "rss shortfall median")] = statistics.median(short)
    figures[("compare", task, "rss shortfall p95")] = percentile(short, 0.95)
    figures[("compare", task, "rss shortfall peak")] = max(short)
    figures[("compare", task, "sampled tasks more than 1 MB short (count)")] = sum(k > 1024 for k in short)
    samples_per = [int(r["samples"]) for r in with_samples]
    figures[("compare", task, "samples per task median")] = statistics.median(samples_per)

    parser_attempts = sum(
        t["attempts"] for t in load["tasks"] if t["module"] in ("email_analyzer", "archive", "yara_scanner_v3_4")
    )
    lookup_attempts = sum(
        t["attempts"] for t in load["tasks"] if t["module"] in ("rdap_analyzer", "proxy_domain_splunk")
    )
    other_attempts = sum(t["attempts"] for t in load["tasks"]) - parser_attempts - lookup_attempts
    figures[("compare", "load", "parser task attempts")] = parser_attempts
    figures[("compare", "load", "lookup task attempts")] = lookup_attempts
    figures[("compare", "load", "other task attempts")] = other_attempts
    figures[("compare", "load", "tasks not done")] = sum(t["count"] for t in load["tasks"] if t["state"] != "done")
    figures[("compare", "load", "roots")] = load["roots"]
    figures[("compare", "load", "results")] = load["results"]
    figures[("compare", "load", "seconds")] = load["compare_seconds"]
    figures[("compare", "load", "exit")] = load["compare_exit"]
    figures[("compare", "load", "report samples")] = load["report"].get("samples", 0)
    figures[("compare", "sampler", "tick ms median")] = meta["tick_ms_median"]
    return figures, rows


def span(values, scale=1.0, digits=1):
    low, middle, high = min(values) * scale, statistics.median(values) * scale, max(values) * scale
    if round(low, digits) == round(high, digits):
        return f"{middle:.{digits}f}", f"{low:.{digits}f}"
    return f"{middle:.{digits}f}", f"{low:.{digits}f} to {high:.{digits}f}"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("out_dir", type=Path)
    parser.add_argument("--series")
    parser.add_argument("--tsv", type=Path)
    parser.add_argument("--tasks-tsv", type=Path)
    args = parser.parse_args()
    series = args.series or args.out_dir.name
    runs = sorted(args.out_dir.glob("run-*"), key=lambda p: int(p.name.split("-")[1]))
    per_run = []
    per_task = []
    for run in runs:
        figures, rows = one_run(run)
        per_run.append(figures)
        per_task.append(rows)

    keys = list(per_run[0])
    print(f"Series {series}: {len(runs)} runs. Memory in MB; counts and milliseconds as they are.\n")
    print("| Phase | Subject | Figure | Median | Range |")
    print("|---|---|---|---|---|")
    plain = ("processes", "running at once", "exit records", "sampled", "non-zero exits", "dropped",
             "lifetime", "cpu ms", "samples per", "attempts", "not done", "roots", "results", "seconds",
             "exit", "report samples", "tick ms", "events", "(count)")
    for key in keys:
        values = [figures[key] for figures in per_run]
        counts = any(word in key[2] for word in plain) and "peak rss" not in key[2]
        median, low_high = span(values, 1.0 if counts else 1 / 1024, 2 if "tick" in key[2] else 1)
        print(f"| {key[0]} | {key[1]} | {key[2]} | {median} | {low_high} |")

    if args.tsv:
        new = not args.tsv.exists()
        with open(args.tsv, "a") as out:
            if new:
                print("series\trun\tphase\tsubject\tfigure\tvalue", file=out)
            for number, figures in enumerate(per_run, 1):
                for (phase, subject, figure), value in figures.items():
                    print(f"{series}\t{number}\t{phase}\t{subject}\t{figure}\t{value}", file=out)
    if args.tasks_tsv:
        new = not args.tasks_tsv.exists()
        with open(args.tasks_tsv, "a") as out:
            names = list(per_task[0][0])
            if new:
                print("series\trun\t" + "\t".join(names), file=out)
            for number, rows in enumerate(per_task, 1):
                for row in rows:
                    print(f"{series}\t{number}\t" + "\t".join(row[n] for n in names), file=out)


if __name__ == "__main__":
    main()
