#!/usr/bin/env python3
"""Extract application-code taint flows from Tai-e run logs.

Tai-e reports every taint flow it finds across ALL reachable methods,
including flows whose sink is inside library/JRE code (JDK internals,
Spring, Hibernate). For the OWASP Benchmark evaluation only flows whose
sink is in the benchmark's own code (``org.owasp.benchmark.*``) count
as candidate findings; the rest is library noise (see PILOT.md).

Usage:
    python3 scripts/extract_app_flows.py --log-dir output/ \\
        --cases-csv data/sample_seed42.csv \\
        --out data/flows.json

Each log file must be named ``taie-<CaseName>.log`` or
``taie-pilot-<CaseName>.log`` (e.g. ``taie-pilot-00438-r3.log`` is also
accepted: the case name is the first ``BenchmarkTestNNNNN`` token in the
file name). The output is a JSON list, one record per app flow, in the
shape consumed by ``scripts/build_slices.py``.
"""

import argparse
import csv
import json
import re
import sys
from pathlib import Path

APP_PREFIX = "org.owasp.benchmark."

# TaintFlow{<source point> -> <sink point>}
FLOW_RE = re.compile(r"^TaintFlow\{(.*)\}\s*$")
# A point: <method signature>[N@Lline] statement/indexRef   (call site)
#       or <method signature>/param                        (param source)
# The signature itself may contain "<init>" / "<clinit>", so the closing
# ">" is the one followed by "[", "/" or end-of-string.
POINT_RE = re.compile(
    r"^<(?P<method>.+?)>(?=\[|/|$)"
    r"(?:\[(?P<idx>\d+)@L(?P<line>\d+)\]\s+(?P<stmt>.*))?"
    r"(?:/(?P<ref>\S+))?$"
)
METHOD_RE = re.compile(r"^(?P<class>[^:]+):\s*(?P<decl>.+)$")


def parse_method(sig):
    """Split a Tai-e method signature into (class, method_name, decl)."""
    m = METHOD_RE.match(sig)
    if not m:
        return sig, "", sig
    cls = m.group("class")
    decl = m.group("decl")
    name = decl.split("(")[0].strip().split()[-1]
    return cls, name, decl


def parse_point(text):
    """Parse one source/sink point into a dict (or None if unparsable)."""
    m = POINT_RE.match(text.strip())
    if not m:
        return None
    cls, name, decl = parse_method(m.group("method"))
    stmt = m.group("stmt") or ""
    ref = m.group("ref") or ""
    line = m.group("line")
    return {
        "method": m.group("method"),
        "class": cls,
        "method_name": name,
        "decl": decl,
        "line": int(line) if line else None,
        "stmt": stmt,
        "ref": ref,
    }


def parse_flow(line):
    """Parse one 'Detected ... TaintFlow{...}' log line (or None)."""
    m = FLOW_RE.match(line.strip())
    if not m:
        return None
    inner = m.group(1)
    parts = re.split(r" -> (?=<)", inner, maxsplit=1)
    if len(parts) != 2:
        return None
    src = parse_point(parts[0])
    snk = parse_point(parts[1])
    if src is None or snk is None:
        return None
    return {"source": src, "sink": snk, "raw": line.strip()}


def case_from_filename(path):
    m = re.search(r"(BenchmarkTest\d+)", path.name)
    return m.group(1) if m else None


def load_cases(csv_path):
    """Map test_name -> {cwe, real_vulnerability} from the sample CSV."""
    cases = {}
    with open(csv_path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            cases[row["test_name"]] = {
                "cwe": int(row["cwe"]),
                "real_vulnerability": row["real_vulnerability"].strip().lower() == "true",
            }
    return cases


def extract_log(log_path, cases):
    """Extract app flows from one log file. Returns (flows, raw_count)."""
    case = case_from_filename(log_path)
    if case is None:
        return [], 0
    info = cases.get(case, {})
    flows, raw_count = [], 0
    text = log_path.read_text(encoding="utf-8", errors="replace")
    for line in text.splitlines():
        if "TaintFlow{" not in line:
            continue
        raw_count += 1
        flow = parse_flow(line)
        if flow is None:
            continue
        if not flow["sink"]["class"].startswith(APP_PREFIX):
            continue
        flow["case"] = case
        flow["cwe"] = info.get("cwe")
        flow["real_vulnerability"] = info.get("real_vulnerability")
        flows.append(flow)
    return flows, raw_count


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log-dir", required=True, help="Directory holding taie-*.log files.")
    parser.add_argument("--cases-csv", required=True, help="Sample CSV (test_name,category,real_vulnerability,cwe).")
    parser.add_argument("--out", required=True, help="Output JSON path (list of app flows).")
    parser.add_argument("--pattern", default="taie-*.log", help="Log filename glob (default: taie-*.log).")
    args = parser.parse_args(argv)

    cases = load_cases(args.cases_csv)
    log_dir = Path(args.log_dir)
    all_flows, summary = [], {}
    for log_path in sorted(log_dir.glob(args.pattern)):
        flows, raw_count = extract_log(log_path, cases)
        case = case_from_filename(log_path)
        summary[case or log_path.name] = {"raw": raw_count, "app": len(flows)}
        for i, flow in enumerate(flows):
            flow["flow_id"] = f"{flow['case']}-{i}"
        all_flows.extend(flows)

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(all_flows, fh, indent=2, ensure_ascii=False)
    n_cases = len([s for s in summary.values() if s["raw"] > 0])
    print(f"{len(all_flows)} app flows from {n_cases} logs "
          f"({sum(s['raw'] for s in summary.values())} raw flows) -> {args.out}")
    for case, counts in sorted(summary.items()):
        if counts["raw"]:
            print(f"  {case}: raw={counts['raw']} app={counts['app']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
