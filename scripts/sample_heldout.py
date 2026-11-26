#!/usr/bin/env python3
"""Draw a held-out sample from OWASP BenchmarkJava, excluding the main sample.

The held-out set validates the final N1 system on cases the prompt was
never tuned on (the 8 pilot cases are all inside the main 240-case
sample, so the prompt rules were tuned on test data) and that N3 was
never designed from (N3 came out of the failure analysis of the 240).

Default: 80 cases, 10 vulnerable + 10 safe per CWE (22, 78, 79, 89),
seed 43, drawn from the 2,500 cases outside data/sample_seed42.csv.

Usage (from the repo root on the machine that has the data):
    python3 scripts/sample_heldout.py
    python3 scripts/sample_heldout.py --seed 43 --vuln-per-cwe 10 --safe-per-cwe 10

Then run the standard pipeline on the held-out set (same fixed config):
    scripts/run_taie_batch.sh --cases-csv data/sample_heldout_seed43.csv --log-dir logs-heldout
    python3 scripts/extract_app_flows.py --log-dir logs-heldout --cases-csv data/sample_heldout_seed43.csv --out data/flows_heldout.json
    python3 scripts/build_slices.py --flows data/flows_heldout.json --src-root benchmarkjava/src/main/java --out data/llm_input_heldout.json
    python3 scripts/llm_adjudicate.py --model qwen3-coder-next --input data/llm_input_heldout.json --output data/llm_output_heldout.jsonl
    python3 scripts/apply_grounding.py --llm-input data/llm_input_heldout.json --llm-output data/llm_output_heldout.jsonl --flows data/flows_heldout.json --cases-csv data/sample_heldout_seed43.csv --grounded-out data/grounded_heldout.jsonl --pred-n1 data/predictions_heldout.csv --pred-n2 data/predictions_heldout_noground.csv --pred-b0 data/predictions_heldout_b0.csv
    python3 scripts/score.py --predictions data/predictions_heldout.csv --ground-truth data/sample_heldout_seed43.csv
    python3 scripts/score.py --predictions data/predictions_heldout_b0.csv --ground-truth data/sample_heldout_seed43.csv

The ground-truth file (expectedresults-1.2.csv) has no header row: its
first line is a '#' comment, then rows of
    test_name, category, real_vulnerability, cwe
"""

import argparse
import csv
import random
from collections import defaultdict

CWES = ("22", "78", "79", "89")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=43)
    ap.add_argument("--vuln-per-cwe", type=int, default=10)
    ap.add_argument("--safe-per-cwe", type=int, default=10)
    ap.add_argument("--ground-truth", default="data/expectedresults-1.2.csv")
    ap.add_argument("--exclude", default="data/sample_seed42.csv")
    ap.add_argument("--out", default="data/sample_heldout_seed43.csv")
    args = ap.parse_args()

    excluded = set()
    with open(args.exclude) as f:
        reader = csv.DictReader(f)
        for row in reader:
            excluded.add(row["test_name"])

    by_cell = defaultdict(list)  # (cwe, real_vuln) -> [test_name, ...]
    with open(args.ground_truth) as f:
        for line in f:
            if line.startswith("#"):
                continue
            parts = [p.strip() for p in line.strip().split(",")]
            if len(parts) < 4:
                continue
            name, _category, vuln_str, cwe = parts[:4]
            if name in excluded or cwe not in CWES:
                continue
            by_cell[(cwe, vuln_str.lower() == "true")].append(name)

    rng = random.Random(args.seed)
    picked = []  # (test_name, category, real_vulnerability, cwe)
    category = {"22": "pathtraver", "78": "cmdi", "79": "xss", "89": "sqli"}
    for cwe in CWES:
        for vuln, n in ((True, args.vuln_per_cwe), (False, args.safe_per_cwe)):
            pool = sorted(by_cell[(cwe, vuln)])
            if len(pool) < n:
                raise SystemExit(
                    f"not enough held-out cases for CWE-{cwe} "
                    f"{'vuln' if vuln else 'safe'}: need {n}, have {len(pool)}"
                )
            rng.shuffle(pool)
            for name in pool[:n]:
                picked.append((name, category[cwe], str(vuln).lower(), cwe))
    picked.sort()

    with open(args.out, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["test_name", "category", "real_vulnerability", "cwe"])
        writer.writerows(picked)
    n_vuln = sum(1 for _, _, v, _ in picked if v == "true")
    print(
        f"wrote {len(picked)} cases to {args.out} "
        f"({n_vuln} vulnerable, {len(picked) - n_vuln} safe)"
    )


if __name__ == "__main__":
    main()
