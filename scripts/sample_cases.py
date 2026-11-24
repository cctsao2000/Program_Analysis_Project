#!/usr/bin/env python3
"""Stratified sampling of OWASP BenchmarkJava cases.

Reads the benchmark ground-truth CSV (``expectedresults-1.2.csv``) and draws
a seeded, per-CWE sample balanced between vulnerable (``true``) and safe
(``false``) cases. Every method under comparison must be evaluated on the
same sampled cases; the seed and the sample file are part of the artifact.

Ground-truth CSV format (first line is a ``#`` comment header)::

    BenchmarkTest00001,pathtraver,true,22

Usage:
    python3 scripts/sample_cases.py --csv data/expectedresults-1.2.csv \
        --cwes 89,79,22,78 --per-cwe 60 --seed 42 \
        --output data/sample_seed42.csv
"""

import argparse
import csv
import random
import sys
from collections import defaultdict
from pathlib import Path


def load_cases(csv_path):
    """Return a list of dicts with test_name, category, real_vuln, cwe."""
    cases = []
    with open(csv_path, newline="") as f:
        for row in csv.reader(f):
            if not row or row[0].startswith("#"):
                continue
            name, category, real, cwe = [c.strip() for c in row[:4]]
            cases.append(
                {
                    "test_name": name,
                    "category": category,
                    "real_vulnerability": real.lower(),
                    "cwe": cwe,
                }
            )
    return cases


def stratified_sample(cases, cwes, per_cwe, seed):
    rng = random.Random(seed)
    by_cwe_vuln = defaultdict(lambda: {"true": [], "false": []})
    for case in cases:
        if case["cwe"] in cwes:
            by_cwe_vuln[case["cwe"]][case["real_vulnerability"]].append(case)

    sampled = []
    for cwe in cwes:
        pools = by_cwe_vuln[cwe]
        n_vuln = (per_cwe + 1) // 2  # odd per_cwe: extra case is vulnerable
        n_safe = per_cwe - n_vuln
        for label, n in (("true", n_vuln), ("false", n_safe)):
            pool = pools[label]
            if n > len(pool):
                raise ValueError(
                    f"CWE-{cwe}: requested {n} {label} cases, only {len(pool)} available"
                )
            sampled.extend(rng.sample(pool, n))
    rng.shuffle(sampled)
    return sampled


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", type=Path, required=True,
                        help="Path to expectedresults-1.2.csv")
    parser.add_argument("--cwes", default="89,79,22,78",
                        help="Comma-separated CWE ids (default: 89,79,22,78)")
    parser.add_argument("--per-cwe", type=int, default=60,
                        help="Cases per CWE, split evenly vuln/safe (default: 60)")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    cwes = [c.strip() for c in args.cwes.split(",")]
    cases = load_cases(args.csv)
    sampled = stratified_sample(cases, cwes, args.per_cwe, args.seed)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", newline="") as f:
        writer = csv.DictWriter(
            f, fieldnames=["test_name", "category", "real_vulnerability", "cwe"]
        )
        writer.writeheader()
        writer.writerows(sampled)

    counts = defaultdict(lambda: {"true": 0, "false": 0})
    for case in sampled:
        counts[case["cwe"]][case["real_vulnerability"]] += 1
    print(f"sampled {len(sampled)} cases (seed={args.seed}) -> {args.output}")
    for cwe in cwes:
        c = counts[cwe]
        print(f"  CWE-{cwe}: {c['true']} vulnerable, {c['false']} safe")
    return 0


if __name__ == "__main__":
    sys.exit(main())
