#!/usr/bin/env python3
"""Symbolic grounding checker for LLM adjudications (skeleton, runnable).

Design: the LLM adjudicates a candidate taint flow flagged by Tai-e and
must cite evidence for any ``FP`` verdict. Evidence has two kinds:

* ``sanitizer``: a sanitizer API plus the source line where it is
  applied (the API string must appear on that line);
* ``constant``: the source line where a constant value is assigned or
  where a constant condition appears (the line must contain a string
  or numeric literal) — for FPs where the value is hard-coded or the
  tainted branch is dead, so there is no sanitizer API to cite.

This checker verifies the citation against the actual code slice,
without any LLM involvement:

* cited line must exist in the slice (1-based);
* for ``sanitizer``, the cited API string must appear on that line
  (case-sensitive substring);
* for ``constant``, the cited line must contain a string or numeric
  literal;
* an ``FP`` verdict with missing or failed evidence is downgraded to
  ``uncertain`` and the conservative fallback keeps the baseline verdict
  (the flow stays flagged).

Evidence is only load-bearing for ``FP`` verdicts: a ``TP`` verdict agrees
with the baseline, so failed ``TP`` evidence is reported but does not
change the verdict.

Judgement JSON format (see ``prompts/adjudicate.md``)::

    {"verdict": "TP" | "FP" | "uncertain",
     "evidence": {"kind": "sanitizer" | "constant",
                  "api": "..." | null, "line": 12} | null,
     "reasoning": "...", "confidence": 0.0-1.0}

The older ``sanitizer_evidence`` key ({"api": ..., "line": ...}) is still
accepted and treated as kind ``sanitizer``.

Usage:
    python3 src/grounding_check.py --slice examples/toy_slice.java \\
        --judgement examples/toy_judgement_fp_pass.json --baseline flagged
"""

import argparse
import json
import re
import sys
from pathlib import Path

VERDICTS = ("TP", "FP", "uncertain")
_LITERAL_RE = re.compile(r'"[^"]*"|\b\d+(?:\.\d+)?\b')


def _resolve_line(lines, line_no):
    """Return the code text for a cited line number.

    Slices are presented to the LLM with original file line numbers as
    an ``NNN: `` prefix, so a cited number is first matched against
    those prefixes; otherwise it is treated as a 1-based position in
    the slice text. Returns None when the number cannot be resolved.
    """
    prefix = str(line_no) + ":"
    for text in lines:
        if text.startswith(prefix):
            return text[len(prefix):]
    if 1 <= line_no <= len(lines):
        return lines[line_no - 1]
    return None


def check_evidence(evidence, lines):
    """Validate one evidence citation against slice lines (1-based).

    Returns (passed: bool, detail: str). Accepts the current
    ``evidence`` object ({"kind": "sanitizer"|"constant", "api", "line"})
    and the older ``sanitizer_evidence`` object ({"api", "line"}).
    """
    if not isinstance(evidence, dict):
        return False, "evidence is not an object"
    kind = evidence.get("kind", "sanitizer")
    line_no = evidence.get("line")
    if not isinstance(line_no, int) or isinstance(line_no, bool):
        return False, "evidence.line must be an integer"
    line_text = _resolve_line(lines, line_no)
    if line_text is None:
        return False, f"line {line_no} not found in slice ({len(lines)} lines)"
    if kind == "constant":
        if _LITERAL_RE.search(line_text):
            return True, f"line {line_no} contains a literal: {line_text.strip()!r}"
        return False, f"line {line_no} has no string/numeric literal: {line_text.strip()!r}"
    if kind != "sanitizer":
        return False, f"unknown evidence kind {kind!r}"
    api = evidence.get("api")
    if not isinstance(api, str) or not api:
        return False, "evidence.api must be a non-empty string"
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

    evidence = judgement.get("evidence")
    if evidence is None:
        # Backward compatibility with the earlier schema.
        evidence = judgement.get("sanitizer_evidence")
    if verdict == "FP":
        if evidence is None:
            checks.append("FP verdict without evidence")
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
