#!/usr/bin/env python3
"""Apply the symbolic grounding checker to LLM adjudication outputs.

Joins the LLM input (slices, from ``scripts/build_slices.py``) with the
LLM output (parsed verdicts, from ``scripts/llm_adjudicate.py``) by
flow_id, runs ``src/grounding_check.adjudicate`` per flow, and writes:

* ``--grounded-out`` (JSONL): one record per flow with the LLM verdict,
  the grounding result and the final verdict (flagged / cleared /
  uncertain).
* ``--pred-n1`` (CSV): case-level predictions for N1 (Tai-e + LLM +
  grounding). A case is predicted vulnerable iff at least one of its
  flows ends ``flagged``.
* ``--pred-n2`` (CSV): case-level predictions for N2 (same LLM verdicts
  with the grounding check disabled). A case is predicted vulnerable
  iff at least one flow has an LLM verdict of TP or uncertain, or a
  parse error (the conservative fallback keeps the baseline flag).
* ``--pred-b0`` (CSV, requires ``--flows``): case-level baseline
  predictions (Tai-e alone). A case is predicted vulnerable iff it has
  at least one app flow.

All prediction CSVs cover every case in ``--cases-csv`` (cases with no
app flows are predicted safe). They are directly consumable by
``scripts/score.py``.

Usage:
    python3 scripts/apply_grounding.py \\
        --llm-input data/llm_input.json --llm-output data/llm_output.jsonl \\
        --flows data/flows.json --cases-csv data/sample_seed42.csv \\
        --grounded-out data/grounded.jsonl \\
        --pred-n1 data/predictions_n1.csv --pred-n2 data/predictions_n2.csv \\
        --pred-b0 data/predictions_b0.csv
"""

import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from grounding_check import adjudicate  # noqa: E402


def load_cases(csv_path):
    with open(csv_path, newline="", encoding="utf-8") as fh:
        return [row["test_name"] for row in csv.DictReader(fh)]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--llm-input", required=True)
    parser.add_argument("--llm-output", required=True)
    parser.add_argument("--flows", default=None)
    parser.add_argument("--cases-csv", required=True)
    parser.add_argument("--grounded-out", required=True)
    parser.add_argument("--pred-n1", required=True)
    parser.add_argument("--pred-n2", required=True)
    parser.add_argument("--pred-b0", default=None)
    args = parser.parse_args(argv)

    slices = {e["flow_id"]: e["slice"] for e in json.loads(Path(args.llm_input).read_text(encoding="utf-8"))}
    outputs = [json.loads(line) for line in Path(args.llm_output).read_text(encoding="utf-8").splitlines() if line.strip()]

    grounded, counts = [], Counter()
    n1_flagged = defaultdict(bool)   # case -> any flow ends flagged (N1)
    n2_flagged = defaultdict(bool)   # case -> any flow TP/uncertain/parse_error (N2)
    for rec in outputs:
        fid = rec["flow_id"]
        case = rec["case"]
        parsed = rec.get("parsed")
        if parsed is None:
            # No usable LLM verdict: conservative fallback keeps the flag.
            result = {"final_verdict": "flagged", "grounding_status": "llm_parse_error",
                      "checks": [rec.get("parse_error") or "no parsed verdict"]}
            llm_verdict = None
        else:
            result = adjudicate(parsed, slices.get(fid, ""), baseline_flagged=True)
            llm_verdict = parsed.get("verdict")
        final = result["final_verdict"]
        counts[final] += 1
        counts[f"llm_{llm_verdict}"] += 1
        if final == "flagged":
            n1_flagged[case] = True
        if llm_verdict in ("TP", "uncertain") or parsed is None:
            n2_flagged[case] = True
        grounded.append({
            "flow_id": fid, "case": case, "cwe": rec.get("cwe"),
            "llm_verdict": llm_verdict, "final_verdict": final,
            "grounding_status": result["grounding_status"],
            "checks": result["checks"],
        })

    Path(args.grounded_out).parent.mkdir(parents=True, exist_ok=True)
    with open(args.grounded_out, "w", encoding="utf-8") as fh:
        for row in grounded:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")

    cases = load_cases(args.cases_csv)
    b0_flagged = set()
    if args.flows:
        for flow in json.loads(Path(args.flows).read_text(encoding="utf-8")):
            b0_flagged.add(flow["case"])

    def write_pred(path, flagged):
        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(["test_name", "prediction"])
            for case in cases:
                writer.writerow([case, "true" if flagged.get(case) else "false"])

    write_pred(args.pred_n1, n1_flagged)
    write_pred(args.pred_n2, n2_flagged)
    if args.pred_b0:
        write_pred(args.pred_b0, {c: True for c in b0_flagged})

    print(f"{len(grounded)} flows grounded: {dict(counts)}")
    print(f"N1 vulnerable cases: {sum(1 for c in cases if n1_flagged.get(c))}/{len(cases)}")
    print(f"N2 vulnerable cases: {sum(1 for c in cases if n2_flagged.get(c))}/{len(cases)}")
    if args.pred_b0:
        print(f"B0 vulnerable cases: {len(b0_flagged)}/{len(cases)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
