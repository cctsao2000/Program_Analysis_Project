# LLM adjudication prompt (draft)

Status: draft, 2026-11-18. Not yet run against any model. The prompt,
the model ID, the temperature, and every raw LLM output must be recorded
in the artifact repository for the runs that produce reported numbers.

## Role of this prompt

Tai-e (the symbolic baseline) enumerates candidate taint flows. This
prompt asks the LLM to adjudicate **one** candidate flow: is it a real,
exploitable vulnerability of the stated CWE, or a false positive because
the data is sanitized, validated, or otherwise neutralised on the way
from source to sink? The LLM's verdict is then checked by the symbolic
grounding checker (`src/grounding_check.py`), which verifies that any
cited sanitizer evidence actually appears in the code slice. An `FP`
verdict with unverifiable evidence is downgraded to `uncertain` and the
baseline verdict (flagged) is kept.

## Model settings (to be fixed before the first scored run)

- Provider: SoCLaaS (OpenAI-compatible API). API key **only** from the
  `SOCLAAS_API_KEY` environment variable. Never commit a key.
- Temperature: 0 (deterministic). Record the exact model ID returned by
  `GET /v1/models`, the prompt text (this file, by commit), and the
  date of each run.
- Ablation N0 ("LLM alone") uses the same prompt with the `FLOW FACTS`
  block removed. Ablation N2 reuses N1 outputs with the grounding check
  disabled; no extra LLM calls.

## Prompt template

Placeholders: `{{CWE}}`, `{{CWE_NAME}}`, `{{FLOW_FACTS}}`, `{{SLICE}}`.
`{{SLICE}}` is the source file (or minimal enclosing-method slice) with
1-based line numbers. `{{FLOW_FACTS}}` is Tai-e's reported flow: source
method + location, sink method + location, and intermediate methods.

```text
You are a security analyst reviewing one candidate taint flow reported
by a static analyzer. Decide whether it is a real vulnerability.

CWE under review: CWE-{{CWE}} ({{CWE_NAME}}).

FLOW FACTS (from the static analyzer; treat the flow path as given,
do not invent additional flows):
{{FLOW_FACTS}}

CODE SLICE (1-based line numbers; only this code is visible to you):
{{SLICE}}

SANITIZER CHECKLIST for CWE-{{CWE}} (see below). A sanitizer counts
only if it is applied to the tainted value on the path from source to
sink AND is effective for this CWE. Encoding or validation meant for a
different vulnerability class does not count.

Rules:
1. Judge only the flow described above and the code in the slice.
2. If you claim the flow is a false positive, you MUST cite the exact
   sanitizer API and the exact line number where it is applied.
   Do not cite APIs or lines that are not in the slice.
3. If the slice does not contain enough information to decide, say
   "uncertain" rather than guessing.
4. A constant, hard-coded, or empty value reaching the sink is not
   attacker-controlled; say so explicitly if that is the case.
5. Keep the reasoning to at most 3 sentences.

Reply with EXACTLY one JSON object, no other text:
{"verdict": "TP" | "FP" | "uncertain",
 "sanitizer_evidence": {"api": "<exact API name as it appears in the code>", "line": <integer>} | null,
 "reasoning": "<at most 3 sentences>",
 "confidence": <number between 0 and 1>}
```

## Per-CWE sanitizer checklists

### CWE-89 SQL injection

Counts as sanitizing:

- Query executed through a `PreparedStatement`/`CallableStatement`
  with `?` placeholders and the tainted value bound via a `set*`
  method (e.g. `setString`), with no string concatenation of tainted
  data into the SQL text.
- Tainted value restricted to a fixed allow-list / enum before use.

Does NOT count:

- HTML encoding (`encodeForHTML`), URL encoding, or generic escaping
  meant for output contexts.
- `Statement` execution of a concatenated query string, even if the
  concatenation uses `StringBuilder` or `String.format`.
- Client-side validation only.

### CWE-79 Cross-site scripting (XSS)

Counts as sanitizing:

- Context-appropriate output encoding applied to the tainted value
  before it reaches the response writer (e.g. ESAPI
  `encodeForHTML` for HTML body context, `encodeForJavaScript` for
  script context, `encodeForURL` for URL context).
- Tainted value restricted to a fixed allow-list before output.

Does NOT count:

- SQL-oriented handling (`PreparedStatement`, SQL escaping).
- Encoding applied to a different value, or after the sink.
- Encoding for the wrong context (e.g. HTML encoding inside a
  `<script>` block does not neutralise script-context XSS).

### CWE-22 Path traversal

Counts as sanitizing:

- Canonicalisation plus a containment check: the resolved path is
  verified to stay under an intended base directory (e.g. via
  `Path.normalize()` + `startsWith(base)`).
- Tainted value restricted to a fixed allow-list of file names.
- Rejection of path separators / `..` sequences with validation that
  actually runs on the tainted value before the sink.

Does NOT count:

- Removing a single `../` occurrence once (bypassable), or validation
  that runs after the file is opened.
- HTML/SQL encoding of any kind.

### CWE-78 OS command injection

Counts as sanitizing:

- Tainted value passed as a separate argument in an argument array /
  list to `ProcessBuilder` or `Runtime.exec(String[])` with no shell
  interpretation, AND the argument is not itself a shell metacharacter
  string executed via a shell (`sh -c`, `cmd /c`).
- Tainted value restricted to a fixed allow-list of commands/arguments.

Does NOT count:

- Passing a single concatenated command string to a shell.
- HTML/SQL encoding, or quoting that the shell still interprets.

## Failure modes to watch for (to be confirmed empirically)

- The model citing a sanitizer that exists in the file but is not on
  the tainted path (the grounding checker catches wrong lines, not
  wrong paths; path membership must be judged from the flow facts).
- The model treating any encoding API as a universal sanitizer.
- The model refusing to commit (`uncertain`) on clearly vulnerable
  flows, or hallucinating line numbers (caught by the checker).
- JSON format failures: log the raw output verbatim and count them;
  do not silently repair outputs before scoring.
