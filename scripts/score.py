#!/usr/bin/env python3
"""Score predictions against OWASP BenchmarkJava ground truth.

Predictions CSV format (header required)::

    test_name,prediction

where ``prediction`` is one of ``true``/``false``, ``vulnerable``/``safe``,
or ``1``/``0`` (case-insensitive). Reports TP/FP/FN/TN, precision, recall
and F1 per CWE and overall.

Usage:
    python3 scripts/score.py --predictions data/predictions.csv \
        --ground-truth data/expectedresults-1.2.csv [--output results.json]

By default every ground-truth case in scope must have a prediction
(``--allow-missing`` downgrades missing predictions to ``safe`` with a
warning). Use ``--cases`` to restrict scoring to a sampled subset file
produced by ``scripts/sample_cases.py``.
"""

import argparse
import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

TRUE_VALUES = {"true", "vulnerable", "1", "yes"}
FALSE_VALUES = {"false", "safe", "0", "no"}


def parse_bool(value, where):
    v = value.strip().lower()
    if v in TRUE_VALUES:
        return True
    if v in FALSE_VALUES:
        return False
    raise ValueError(f"unrecognised boolean {value!r} in {where}")


def load_ground_truth(csv_path):
    """Return {test_name: (is_vulnerable: bool, cwe: str)}."""
    truth = {}
    with open(csv_path, newline="") as f:
        for row in csv.reader(f):
            if not row or row[0].startswith("#"):
                continue
            name, _category, real, cwe = [c.strip() for c in row[:4]]
            truth[name] = (parse_bool(real, f"ground truth row {name}"), cwe)
    return truth


def load_predictions(csv_path):
    predictions = {}
    with open(csv_path, newline="") as f:
        reader = csv.DictReader(f)
        if "test_name" not in reader.fieldnames or "prediction" not in reader.fieldnames:
            raise ValueError("predictions CSV needs test_name,prediction header")
        for row in reader:
            predictions[row["test_name"].strip()] = parse_bool(
                row["prediction"], f"prediction row {row['test_name']}"
            )
    return predictions


def metrics(tp, fp, fn, tn):
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--predictions", type=Path, required=True)
    parser.add_argument("--ground-truth", type=Path, required=True)
    parser.add_argument("--cases", type=Path, default=None,
                        help="Optional sample CSV; score only these cases")
    parser.add_argument("--allow-missing", action="store_true",
                        help="Treat missing predictions as 'safe' (default: error)")
    parser.add_argument("--output", type=Path, default=None,
                        help="Optional JSON file for the metrics")
    args = parser.parse_args(argv)

    truth = load_ground_truth(args.ground_truth)
    predictions = load_predictions(args.predictions)

    if args.cases:
        with open(args.cases, newline="") as f:
            wanted = [row["test_name"] for row in csv.DictReader(f)]
    else:
        wanted = sorted(truth)

    unknown = sorted(set(predictions) - set(truth))
    if unknown:
        print(f"warning: {len(unknown)} predictions with unknown test names, ignored",
              file=sys.stderr)
    missing = [name for name in wanted if name not in predictions]
    if missing and not args.allow_missing:
        raise SystemExit(
            f"error: {len(missing)} cases without predictions (first: {missing[:5]}); "
            "use --allow-missing to score them as 'safe'"
        )
    if missing:
        print(f"warning: {len(missing)} missing predictions scored as 'safe'",
              file=sys.stderr)

    per_cwe = defaultdict(lambda: [0, 0, 0, 0])  # tp, fp, fn, tn
    total = [0, 0, 0, 0]
    for name in wanted:
        is_vuln, cwe = truth[name]
        predicted = predictions.get(name, False)
        idx = (0 if predicted and is_vuln else
               1 if predicted and not is_vuln else
               2 if not predicted and is_vuln else 3)
        per_cwe[cwe][idx] += 1
        total[idx] += 1

    results = {"overall": metrics(*total),
               "per_cwe": {cwe: metrics(*v) for cwe, v in sorted(per_cwe.items())}}

    print(f"{'scope':<10}{'TP':>5}{'FP':>5}{'FN':>5}{'TN':>5}{'P':>8}{'R':>8}{'F1':>8}")
    for scope, m in [("overall", results["overall"])] + sorted(results["per_cwe"].items()):
        print(f"{scope:<10}{m['tp']:>5}{m['fp']:>5}{m['fn']:>5}{m['tn']:>5}"
              f"{m['precision']:>8.4f}{m['recall']:>8.4f}{m['f1']:>8.4f}")
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(results, indent=2) + "\n")
        print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
