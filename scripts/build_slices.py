#!/usr/bin/env python3
"""Build LLM adjudication inputs from extracted app flows.

For each flow, the slice is the enclosing method of the source call
plus the enclosing method of the sink call (deduplicated when they are
the same method), taken from the benchmark source with original file
line numbers. Output is the JSON list consumed by
``scripts/llm_adjudicate.py`` (same schema as
``data/pilot_llm_input.json``).

Method ranges are found by declaration search plus brace matching
(strings and comments are skipped while counting braces). If a method
cannot be located, the slice falls back to a +/-30-line window around
the call site, so a flow is never dropped silently.

Usage:
    python3 scripts/build_slices.py --flows data/flows.json \\
        --src-root benchmarkjava/src/main/java \\
        --out data/llm_input.json

Known limitation: when source and sink live in different files, the
slice has one section per file (each headed by a ``// file:`` line)
and line numbers are per-file; the grounding checker resolves a cited
line against the first matching section unless the evidence names a
file (``evidence["file"]``), in which case it resolves within that
file's sections only. Field definitions are included only for
single-line declarations with an initializer.
"""

import argparse
import json
import re
import sys
from pathlib import Path

CWE_NAMES = {
    89: "SQL Injection",
    79: "Cross-Site Scripting (XSS)",
    22: "Path Traversal",
    78: "OS Command Injection",
}

WINDOW = 30

# A class-level field declaration: optional modifiers, a type, a name,
# an initializer, ending in ';'. The text before the first '=' must not
# contain '(' (that would be a method declaration).
FIELD_RE = re.compile(
    r"^\s*(?:(?:public|private|protected|static|final|transient|volatile)\s+)*"
    r"(?:[\w<>\[\],\s.]+?)\s+(\w+)\s*=\s*.*;\s*$"
)


def _line_depths(lines):
    """Brace depth at the start of each line (strings/comments skipped)."""
    depths, depth = [], 0
    state = "normal"
    for text in lines:
        depths.append(depth)
        j = 0
        while j < len(text):
            ch = text[j]
            nxt = text[j + 1] if j + 1 < len(text) else ""
            if state == "normal":
                if ch == "/" and nxt == "/":
                    break
                if ch == "/" and nxt == "*":
                    state = "block_comment"
                    j += 2
                    continue
                if ch == '"':
                    state = "string"
                    j += 1
                    continue
                if ch == "'":
                    state = "char"
                    j += 1
                    continue
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
            elif state == "block_comment":
                if ch == "*" and nxt == "/":
                    state = "normal"
                    j += 2
                    continue
            elif state == "string":
                if ch == "\\":
                    j += 2
                    continue
                if ch == '"':
                    state = "normal"
            elif state == "char":
                if ch == "\\":
                    j += 2
                    continue
                if ch == "'":
                    state = "normal"
            j += 1
        if state == "line_comment":
            state = "normal"
    return depths


def field_declarations(lines):
    """Class-level field declarations: [(1-based line no, name, text)].

    A field sits at brace depth 1 (inside the class, outside any
    method). Only single-line declarations with an initializer are
    collected; multi-line initializers are a known limitation.
    """
    depths = _line_depths(lines)
    fields = []
    for i, text in enumerate(lines):
        if depths[i] != 1:
            continue
        if "=" not in text:
            continue
        before_eq = text.split("=", 1)[0]
        if "(" in before_eq:
            continue
        m = FIELD_RE.match(text)
        if m:
            fields.append((i + 1, m.group(1), text))
    return fields


def class_to_path(src_root, cls):
    """Map a Tai-e class name to its source file (inner classes -> outer file)."""
    outer = cls.split("$")[0]
    return Path(src_root) / (outer.replace(".", "/") + ".java")


def _scan_brace_range(lines, start_idx, start_col):
    """Given lines and the position of an opening '{', return the index
    (0-based) of the line holding the matching '}' (or None)."""
    depth = 0
    i, col = start_idx, start_col
    state = "normal"  # normal | line_comment | block_comment | string | char
    while i < len(lines):
        text = lines[i]
        j = col
        while j < len(text):
            ch = text[j]
            nxt = text[j + 1] if j + 1 < len(text) else ""
            if state == "normal":
                if ch == "/" and nxt == "/":
                    state = "line_comment"
                    j += 2
                    continue
                if ch == "/" and nxt == "*":
                    state = "block_comment"
                    j += 2
                    continue
                if ch == '"':
                    state = "string"
                    j += 1
                    continue
                if ch == "'":
                    state = "char"
                    j += 1
                    continue
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        return i
            elif state == "line_comment":
                break
            elif state == "block_comment":
                if ch == "*" and nxt == "/":
                    state = "normal"
                    j += 2
                    continue
            elif state == "string":
                if ch == "\\":
                    j += 2
                    continue
                if ch == '"':
                    state = "normal"
            elif state == "char":
                if ch == "\\":
                    j += 2
                    continue
                if ch == "'":
                    state = "normal"
            j += 1
        if state == "line_comment":
            state = "normal"
        i += 1
        col = 0
    return None


def _find_open_brace(lines, from_idx):
    """Find the first '{' at paren depth 0 starting at from_idx.
    Returns (line_idx, col) or None."""
    depth = 0
    state = "normal"
    for i in range(from_idx, len(lines)):
        text = lines[i]
        j = 0
        while j < len(text):
            ch = text[j]
            nxt = text[j + 1] if j + 1 < len(text) else ""
            if state == "normal":
                if ch == "/" and nxt == "/":
                    break
                if ch == "/" and nxt == "*":
                    state = "block_comment"
                    j += 2
                    continue
                if ch == '"':
                    state = "string"
                    j += 1
                    continue
                if ch == "'":
                    state = "char"
                    j += 1
                    continue
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                elif ch == "{" and depth == 0:
                    return i, j
            elif state == "block_comment":
                if ch == "*" and nxt == "/":
                    state = "normal"
                    j += 2
                    continue
            elif state == "string":
                if ch == "\\":
                    j += 2
                    continue
                if ch == '"':
                    state = "normal"
            elif state == "char":
                if ch == "\\":
                    j += 2
                    continue
                if ch == "'":
                    state = "normal"
            j += 1
        if state == "line_comment":
            state = "normal"
    return None


def _method_ranges(lines, name):
    """All (start_idx, end_idx) ranges of methods/constructors named `name`."""
    ranges = []
    if name == "<clinit>":
        pattern = re.compile(r"^\s*static\s*\{")
        for i, text in enumerate(lines):
            if pattern.match(text):
                brace = _find_open_brace(lines, i)
                if brace:
                    end = _scan_brace_range(lines, brace[0], brace[1])
                    if end is not None:
                        ranges.append((i, end))
        return ranges
    if name == "<init>":
        # Constructor: the name is the class simple name; handled by caller
        # via the class name. Fall through to the generic search with a
        # constructor-only pattern.
        return ranges
    pattern = re.compile(r"\b" + re.escape(name) + r"\s*\(")
    for i, text in enumerate(lines):
        if not pattern.search(text):
            continue
        if text.rstrip().endswith(";"):
            continue  # a call, not a declaration
        brace = _find_open_brace(lines, i)
        if not brace:
            continue
        end = _scan_brace_range(lines, brace[0], brace[1])
        if end is not None:
            ranges.append((i, end))
    return ranges


def enclosing_range(lines, method_name, target_line, class_simple=None):
    """Return (start, end) 1-based line range of the method enclosing
    target_line, or a +/-WINDOW fallback window. When target_line is
    None (a /param source point), the method itself is the source, so
    return the named method's range."""
    name = method_name
    if name == "<init>" and class_simple:
        name = class_simple
        pattern = re.compile(
            r"^\s*(?:public|private|protected)\s+" + re.escape(name) + r"\s*\("
        )
        ranges = []
        for i, text in enumerate(lines):
            if pattern.match(text):
                brace = _find_open_brace(lines, i)
                if brace:
                    end = _scan_brace_range(lines, brace[0], brace[1])
                    if end is not None:
                        ranges.append((i, end))
    else:
        ranges = _method_ranges(lines, name)
    if target_line is None:
        # A /param source point: the method itself is the source.
        if ranges:
            start, end = ranges[0]
            return start + 1, end + 1
        return 1, min(len(lines), WINDOW)
    target_idx = target_line - 1
    for start, end in ranges:
        if start <= target_idx <= end:
            return start + 1, end + 1
    lo = max(1, target_line - WINDOW)
    hi = min(len(lines), target_line + WINDOW)
    return lo, hi


def numbered(lines, lo, hi):
    return "\n".join(f"{n}: {lines[n - 1]}" for n in range(lo, hi + 1))


def build_slice(flow, src_root):
    """Build the numbered slice and flow-facts text for one flow."""
    sections = []  # (path, lo, hi)
    seen = set()
    for point in (flow["source"], flow["sink"]):
        cls = point["class"]
        path = class_to_path(src_root, cls)
        if not path.exists():
            continue
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        simple = cls.split("$")[0].split(".")[-1]
        lo, hi = enclosing_range(lines, point["method_name"], point["line"], simple)
        key = (str(path), lo, hi)
        if key in seen:
            continue
        seen.add(key)
        sections.append((path, lines, lo, hi))
    if not sections:
        return "", None, None
    # Field definitions referenced by the slice (N3 slice enrichment):
    # a field used in a method body is often defined in another class
    # (e.g. Utils.TESTFILES_DIR, a constant the taint analysis cannot
    # see through). Include the defining line, with its real line
    # number, so the adjudicator can cite it as constant evidence.
    # The grounding checker resolves such citations by file name
    # (evidence "file"), so cross-file line-number collisions are safe.
    # Field inclusion runs to a fixed point: a field definition can
    # itself reference another field (TESTFILES_DIR is built from
    # USERDIR), and that definition is included too.
    method_text = "\n".join(
        f"// file: {path.name} (lines {lo}-{hi})\n{numbered(lines, lo, hi)}"
        for path, lines, lo, hi in sections
    )
    parts = []
    for path, lines, lo, hi in sections:
        parts.append(f"// file: {path.name} (lines {lo}-{hi})")
        parts.append(numbered(lines, lo, hi))
        # Fixed-point: keep adding fields referenced by the text so far.
        added = []
        searchable = method_text
        while True:
            new = [
                (n, name, text)
                for n, name, text in field_declarations(lines)
                if (n, name) not in [(a[0], a[1]) for a in added]
                and re.search(r"\b" + re.escape(name) + r"\b", searchable)
            ]
            if not new:
                break
            added.extend(new)
            searchable += "\n" + "\n".join(f"{n}: {text}" for n, _name, text in new)
        if added:
            parts.append(f"// file: {path.name} (field definitions)")
            parts.append("\n".join(f"{n}: {text}" for n, _name, text in added))
    primary = sections[0]
    return "\n".join(parts), primary[0], (primary[2], primary[3])


def flow_facts(flow):
    src, snk = flow["source"], flow["sink"]
    src_line = f"line {src['line']}" if src["line"] else "the method parameter"
    return (
        f"Source: <{src['method']}> at {src_line}"
        + (f" ({src['stmt']})" if src["stmt"] else "")
        + f".\nSink: <{snk['method']}> at line {snk['line']}"
        + (f" ({snk['stmt']}, argument index {snk['ref']})" if snk["stmt"] else ".")
        + "\nPath: as reported by the static analyzer (source -> sink); "
        + "the slice shows the enclosing method(s) of the source and the sink, "
        + "plus the definitions of any class fields they reference "
        + "(field definitions are listed per file after the method section)."
    )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--flows", required=True, help="App flows JSON from extract_app_flows.py.")
    parser.add_argument("--src-root", required=True, help="Benchmark source root (…/src/main/java).")
    parser.add_argument("--out", required=True, help="Output JSON path (LLM adjudication input).")
    args = parser.parse_args(argv)

    flows = json.loads(Path(args.flows).read_text(encoding="utf-8"))
    entries, skipped = [], []
    for flow in flows:
        cwe = flow.get("cwe")
        slice_text, primary_path, primary_range = build_slice(flow, args.src_root)
        if not slice_text:
            skipped.append(flow.get("flow_id", "?"))
            continue
        entries.append(
            {
                "flow_id": flow.get("flow_id"),
                "case": flow["case"],
                "cwe": cwe,
                "cwe_name": CWE_NAMES.get(cwe, ""),
                "expected": "TP" if flow.get("real_vulnerability") else "FP",
                "flow_facts": flow_facts(flow),
                "slice": slice_text,
                "slice_file": primary_path.name if primary_path else None,
                "slice_lines": list(primary_range) if primary_range else None,
                "sink_line": flow["sink"]["line"],
            }
        )
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(entries, fh, indent=2, ensure_ascii=False)
    print(f"{len(entries)} slices -> {args.out}" + (f" (skipped: {skipped})" if skipped else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
