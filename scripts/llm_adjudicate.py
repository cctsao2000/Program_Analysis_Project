#!/usr/bin/env python3
"""LLM adjudication harness for the CS6215 project (N1 / N0).

Reads a JSON list of candidate taint flows (each with CWE, flow facts and
a code slice), sends one adjudication prompt per flow to a SoCLaaS
OpenAI-compatible chat model, and writes one JSON record per flow
(prompt, raw output, parsed verdict) as JSONL.

The API key is read ONLY from the SOCLAAS_API_KEY environment variable
(never from a file argument, never printed). Stdlib only, no pip install.

Usage (from the repo root, after `set -a; source soclaas.env; set +a`):
    python3 scripts/llm_adjudicate.py \
        --model qwen3-coder-next \
        --input data/pilot_llm_input.json \
        --output data/pilot_llm_output.jsonl

The prompt template and per-CWE sanitizer checklists are copied from
prompts/adjudicate.md (same wording); the exact prompt sent per flow is
stored in the output file for reproducibility.
"""

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

DEFAULT_BASE_URL = "https://soclaas-api.comp.nus.edu.sg/v1"
DEFAULT_MODEL = "qwen3-coder-next"

PROMPT_TEMPLATE = """You are a security analyst reviewing one candidate taint flow reported
by a static analyzer. Decide whether it is a real vulnerability.

CWE under review: CWE-{cwe} ({cwe_name}).

FLOW FACTS (from the static analyzer; treat the flow path as given,
do not invent additional flows):
{flow_facts}

CODE SLICE (1-based line numbers; only this code is visible to you):
{slice}

SANITIZER CHECKLIST for CWE-{cwe}:
{checklist}

Rules:
1. Judge only the flow described above and the code in the slice.
2. If you claim the flow is a false positive, you MUST cite evidence:
   a sanitizer (kind "sanitizer": the exact API and the exact line
   number where it is applied) or a constant / dead value (kind
   "constant": the exact line number where the constant is assigned
   or where the constant condition appears). Do not cite APIs or
   lines that are not in the slice.
3. If the slice does not contain enough information to decide, say
   "uncertain" rather than guessing.
4. A constant, hard-coded, or empty value reaching the sink is not
   attacker-controlled; say so explicitly if that is the case.
5. Keep the reasoning to at most 3 sentences.
6. Evaluate constant branch conditions: if a condition is built only
   from literals (numbers, arithmetic on literals, e.g.
   `(7*18)+106 > 200`), compute its value. A branch the condition
   rules out is unreachable, and a value that only flows through a
   dead branch does not reach the sink. Do not treat a ternary or
   `if` as genuinely conditional when its condition is a constant
   expression.

7. Verdict meanings: "TP" means the flow IS a real, exploitable
   vulnerability of this CWE (the analyzer was right). "FP" means
   the flow is NOT a real vulnerability (the analyzer's report is a
   false alarm). Your verdict MUST agree with your reasoning: if your
   reasoning concludes there is no vulnerability, the verdict is
   "FP"; if it concludes there is a real vulnerability, the verdict
   is "TP".

Reply with EXACTLY one JSON object, no other text, no markdown fences.
Inside the `reasoning` string, do not use double-quote characters;
use single quotes if you need to quote code.
{{"verdict": "TP" | "FP" | "uncertain",
 "evidence": {{"kind": "sanitizer" | "constant", "api": "<exact API name as it appears in the code, or null for constant>", "line": <integer>}} | null,
 "reasoning": "<at most 3 sentences>",
 "confidence": <number between 0 and 1>}}
"""

CHECKLISTS = {
    "89": """Counts as sanitizing:
- Query executed through a PreparedStatement/CallableStatement with ?
  placeholders and the tainted value bound via a set* method (e.g.
  setString), with no string concatenation of tainted data into the
  SQL text.
- Tainted value restricted to a fixed allow-list / enum before use.
Does NOT count:
- HTML encoding (encodeForHTML), URL encoding, or generic escaping
  meant for output contexts.
- Statement execution of a concatenated query string, even if the
  concatenation uses StringBuilder or String.format.
- Client-side validation only.""",
    "79": """Counts as sanitizing:
- Context-appropriate output encoding applied to the tainted value
  before it reaches the response writer (e.g. ESAPI encodeForHTML
  for HTML body context, encodeForJavaScript for script context,
  encodeForURL for URL context).
- Tainted value restricted to a fixed allow-list before output.
Does NOT count:
- SQL-oriented handling (PreparedStatement, SQL escaping).
- Encoding applied to a different value, or after the sink.
- Encoding for the wrong context.""",
    "22": """Counts as sanitizing:
- Canonicalisation plus a containment check: the resolved path is
  verified to stay under an intended base directory (e.g. via
  Path.normalize() + startsWith(base)).
- Tainted value restricted to a fixed allow-list of file names.
- Rejection of path separators / .. sequences with validation that
  actually runs on the tainted value before the sink.
Does NOT count:
- Removing a single ../ occurrence once (bypassable), or validation
  that runs after the file is opened.
- HTML/SQL encoding of any kind.""",
    "78": """Counts as sanitizing:
- Tainted value passed as a separate argument in an argument array /
  list to ProcessBuilder or Runtime.exec(String[]) with no shell
  interpretation, AND the argument is not itself a shell metacharacter
  string executed via a shell (sh -c, cmd /c).
- Tainted value restricted to a fixed allow-list of commands/arguments.
Does NOT count:
- Passing a single concatenated command string to a shell.
- HTML/SQL encoding, or quoting that the shell still interprets.""",
}


def build_prompt(entry):
    cwe = str(entry["cwe"])
    checklist = CHECKLISTS.get(cwe, "No checklist for this CWE; judge from the CWE name.")
    return PROMPT_TEMPLATE.format(
        cwe=cwe,
        cwe_name=entry.get("cwe_name", ""),
        flow_facts=entry["flow_facts"],
        slice=entry["slice"],
        checklist=checklist,
    )


def call_chat(base_url, api_key, model, prompt, temperature):
    return call_chat_messages(
        base_url,
        api_key,
        model,
        [{"role": "user", "content": prompt}],
        temperature,
    )


def parse_verdict(raw):
    """Parse the model's reply as JSON. Returns (parsed_dict_or_None, error_or_None)."""
    text = raw.strip()
    if text.startswith("```"):
        # Strip a markdown fence (```json ... ```) if the model added one.
        lines = text.splitlines()
        if lines and lines[0].strip().startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    parsed, error = _try_parse(text)
    if parsed is not None:
        return parsed, None
    # Fallback: extract the substring from the first '{' to the last '}'
    # (handles extra prose or fences the strip above missed).
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end > start:
        parsed, error = _try_parse(text[start : end + 1])
        if parsed is not None:
            return parsed, None
    return None, error


def _try_parse(text):
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        return None, f"JSON parse error: {exc}"
    if not isinstance(parsed, dict) or "verdict" not in parsed:
        return None, "parsed JSON has no 'verdict' field"
    if parsed["verdict"] not in ("TP", "FP", "uncertain"):
        return None, f"unknown verdict value: {parsed['verdict']!r}"
    return parsed, None


REPAIR_INSTRUCTION = (
    "Your previous reply was not valid JSON (most likely an unescaped "
    "double-quote character inside the reasoning string broke it). Reply "
    "again with exactly the same verdict and reasoning, as one JSON object "
    "only, with no markdown fences, and do not use any double-quote "
    "characters inside the reasoning string (use single quotes for quoted "
    "code)."
)


def call_chat_messages(base_url, api_key, model, messages, temperature):
    body = json.dumps(
        {"model": model, "messages": messages, "temperature": temperature}
    ).encode("utf-8")
    req = urllib.request.Request(
        base_url.rstrip("/") + "/chat/completions",
        data=body,
        headers={
            "Authorization": "Bearer " + api_key,
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=300) as resp:
        return json.loads(resp.read().decode("utf-8"))


def main(argv=None):
    parser = argparse.ArgumentParser(description="Adjudicate taint flows with a SoCLaaS chat model.")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--input", required=True, help="JSON list of flows (see data/pilot_llm_input.json).")
    parser.add_argument("--output", required=True, help="JSONL output path (one record per flow).")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--limit", type=int, default=0, help="Only run the first N flows (0 = all).")
    parser.add_argument("--flow-ids", default="", help="Comma-separated flow_ids to run (default: all).")
    parser.add_argument("--delay", type=float, default=0.5, help="Seconds to wait between calls.")
    args = parser.parse_args(argv)

    api_key = os.environ.get("SOCLAAS_API_KEY")
    if not api_key:
        print("error: SOCLAAS_API_KEY is not set (run: set -a; source soclaas.env; set +a)", file=sys.stderr)
        return 2

    with open(args.input, encoding="utf-8") as fh:
        entries = json.load(fh)
    if args.flow_ids:
        wanted = {fid.strip() for fid in args.flow_ids.split(",") if fid.strip()}
        entries = [e for e in entries if e.get("flow_id") in wanted]
    if args.limit:
        entries = entries[: args.limit]

    counts = {"TP": 0, "FP": 0, "uncertain": 0, "parse_error": 0}
    with open(args.output, "w", encoding="utf-8") as out:
        for i, entry in enumerate(entries):
            prompt = build_prompt(entry)
            attempts = []
            try:
                resp = call_chat(args.base_url, api_key, args.model, prompt, args.temperature)
                raw = resp["choices"][0]["message"]["content"]
                usage = resp.get("usage")
            except (urllib.error.URLError, KeyError, IndexError) as exc:
                raw = ""
                usage = None
                parsed, error = None, f"API call failed: {exc}"
                attempts.append({"raw_output": raw, "parse_error": error})
            else:
                parsed, error = parse_verdict(raw)
                attempts.append({"raw_output": raw, "parse_error": error})
                if parsed is None:
                    # One repair attempt: show the model its broken reply
                    # and ask for the same verdict as clean JSON.
                    try:
                        repair_resp = call_chat_messages(
                            args.base_url,
                            api_key,
                            args.model,
                            [
                                {"role": "user", "content": prompt},
                                {"role": "assistant", "content": raw},
                                {"role": "user", "content": REPAIR_INSTRUCTION},
                            ],
                            args.temperature,
                        )
                        raw2 = repair_resp["choices"][0]["message"]["content"]
                        usage = repair_resp.get("usage", usage)
                    except (urllib.error.URLError, KeyError, IndexError) as exc:
                        raw2 = ""
                        parsed, error = None, f"repair call failed: {exc}"
                        attempts.append({"raw_output": raw2, "parse_error": error})
                    else:
                        parsed, error = parse_verdict(raw2)
                        attempts.append({"raw_output": raw2, "parse_error": error})
                        if parsed is not None:
                            raw = raw2
            verdict = parsed["verdict"] if parsed else "parse_error"
            counts[verdict] = counts.get(verdict, 0) + 1
            record = {
                "flow_id": entry.get("flow_id", f"flow-{i}"),
                "case": entry.get("case"),
                "cwe": str(entry["cwe"]),
                "model": args.model,
                "temperature": args.temperature,
                "prompt": prompt,
                "raw_output": raw,
                "parsed": parsed,
                "parse_error": error,
                "usage": usage,
                "attempts": attempts,
            }
            out.write(json.dumps(record, ensure_ascii=False) + "\n")
            out.flush()
            print(f"[{i + 1}/{len(entries)}] {record['case']} CWE-{record['cwe']}: {verdict}"
                  + (f" (conf {parsed.get('confidence')})" if parsed else f" ({error})"))
            if i + 1 < len(entries) and args.delay:
                time.sleep(args.delay)

    print(f"done: {counts} -> {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
