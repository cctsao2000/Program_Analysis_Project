#!/usr/bin/env python3
"""Symbolic grounding checker for LLM adjudications (skeleton, runnable).

Design: the LLM adjudicates a candidate taint flow flagged by Tai-e and
must cite evidence (a sanitizer API plus the source line where it is
applied) for any ``FP`` verdict. This checker verifies the citation
against the actual code slice, without any LLM involvement:

* cited line must exist in the slice (1-based);
* the cited API string must appear on that line (case-sensitive substring);
* an ``FP`` verdict with missing or failed evidence is downgraded to
  ``uncertain`` and the conservative fallback keeps the baseline verdict
  (the flow stays flagged).

Evidence is only load-bearing for ``FP`` verdicts: a ``TP`` verdict agrees
with the baseline, so failed ``TP`` evidence is reported but does not
change the verdict.

Judgement JSON format (see ``prompts/adjudicate.md``)::

    {"verdict": "TP" | "FP" | "uncertain",
     "sanitizer_evidence": {"api": "...", "line": 12} | null,
     "reasoning": "...", "confidence": 0.0-1.0}

Usage:
    python3 src/grounding_check.py --slice examples/toy_slice.java \\
        --judgement examples/toy_judgement_fp_pass.json --baseline flagged
"""

import argparse
import json
import sys
from pathlib import Path

VERDICTS = ("TP", "FP", "uncertain")


def check_evidence(evidence, lines):
    """Validate one evidence citation against slice lines (1-based).

    Returns (passed: bool, detail: str).
    """
    if not isinstance(evidence, dict):
        return False, "evidence is not an object"
    api = evidence.get("api")
    line_no = evidence.get("line")
    if not isinstance(api, str) or not api:
        return False, "evidence.api must be a non-empty string"
    if not isinstance(line_no, int) or isinstance(line_no, bool):
        return False, "evidence.line must be an integer"
    if line_no < 1 or line_no > len(lines):
        return False, f"line {line_no} out of range (slice has {len(lines)} lines)"
    line_text = lines[line_no - 1]
    if api not in line_text:
        return False, f"api {api!r} not found on line {line_no}: {line_text.strip()!r}"
    return True, f"api {api!r} found on line {line_no}"


def adjudicate(judgement, slice_text, baseline_flagged):
    """Apply grounding checks and the conservative fallback.

    Returns a result dict with ``final_verdict`` in {"flagged", "cleared",
    "uncertain"} from the perspective of the combined analyzer.
    """
    lines = slice_text.splitlines()
    checks = []
    verdict = judgement.get("verdict")
    if verdict not in VERDICTS:
        return {
            "final_verdict": "flagged" if baseline_flagged else "uncertain",
            "grounding_status": "invalid_judgement",
            "checks": [f"invalid verdict {verdict!r}; expected one of {VERDICTS}"],
        }
    confidence = judgement.get("confidence")
    if not isinstance(confidence, (int, float)) or not 0.0 <= confidence <= 1.0:
        checks.append(f"confidence {confidence!r} outside [0, 1] (reported, not fatal)")

    evidence = judgement.get("sanitizer_evidence")
    if verdict == "FP":
        if evidence is None:
            checks.append("FP verdict without sanitizer evidence")
            return {"final_verdict": "flagged" if baseline_flagged else "uncertain",
                    "grounding_status": "no_evidence", "checks": checks}
        passed, detail = check_evidence(evidence, lines)
        checks.append(detail)
        if not passed:
            # Conservative fallback: unverifiable FP claim keeps the flag.
            return {"final_verdict": "flagged" if baseline_flagged else "uncertain",
                    "grounding_status": "failed", "checks": checks}
        return {"final_verdict": "cleared",
                "grounding_status": "pass", "checks": checks}

    if verdict == "TP":
        if evidence is not None:
            passed, detail = check_evidence(evidence, lines)
            checks.append("TP evidence check: " + detail)
            status = "pass" if passed else "failed_non_load_bearing"
        else:
            status = "not_required"
        return {"final_verdict": "flagged",
                "grounding_status": status, "checks": checks}

    # verdict == "uncertain": keep the baseline verdict.
    return {"final_verdict": "flagged" if baseline_flagged else "uncertain",
            "grounding_status": "not_required",
            "checks": checks + ["uncertain verdict keeps baseline verdict"]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--slice", type=Path, required=True,
                        help="Code slice file (1-based line numbers)")
    parser.add_argument("--judgement", type=Path, required=True,
                        help="LLM adjudication JSON file")
    parser.add_argument("--baseline", choices=("flagged", "not_flagged"),
                        default="flagged",
                        help="Tai-e baseline verdict for this case")
    parser.add_argument("--output", type=Path, default=None,
                        help="Write result JSON here (default: stdout)")
    args = parser.parse_args(argv)

    judgement = json.loads(args.judgement.read_text())
    result = adjudicate(judgement, args.slice.read_text(),
                        baseline_flagged=(args.baseline == "flagged"))
    result["llm_verdict"] = judgement.get("verdict")
    text = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.write_text(text)
    else:
        print(text, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
