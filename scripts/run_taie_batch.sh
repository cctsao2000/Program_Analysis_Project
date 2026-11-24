#!/usr/bin/env bash
# Run the Tai-e baseline over the whole 240-case sample, one case at a time.
#
# Fixed configuration (validated by the 8-case pilot, 2026-11-24):
#   --heap 4g, --pta-opts "reflection-inference:null", no only-app,
#   entry points limited to the one case via CS6215_ENTRY_CLASS.
# Each case takes ~25-30s, so the full sample takes roughly 2 hours.
# Run it in the background (nohup ... &) or in a tmux session.
#
# Usage (from the repo root; CP and JAVA_HOME must already be set):
#   scripts/run_taie_batch.sh [--cases-csv data/sample_seed42.csv]
#                             [--log-dir output] [--resume]
#
# --resume skips cases whose log already contains a "Detected" line.
# Per-case summary lines go to stdout AND to <log-dir>/batch-summary.tsv
# (case, raw Detected count, app-flow count).

set -u
CASES_CSV="data/sample_seed42.csv"
LOG_DIR="output"
RESUME=0
while [ $# -gt 0 ]; do
  case "$1" in
    --cases-csv) CASES_CSV="$2"; shift 2 ;;
    --log-dir) LOG_DIR="$2"; shift 2 ;;
    --resume) RESUME=1; shift ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

if [ -z "${CP:-}" ]; then
  echo "error: CP is not set (CP=\"benchmarkjava/target/classes:\$(cat /tmp/bench-cp.txt)\")" >&2
  exit 1
fi
if [ -z "${JAVA_HOME:-}" ]; then
  echo "error: JAVA_HOME is not set" >&2
  exit 1
fi
mkdir -p "$LOG_DIR"
SUMMARY="$LOG_DIR/batch-summary.tsv"
[ "$RESUME" = 0 ] && : > "$SUMMARY"

N=0
while IFS=, read -r test_name _category _real _cwe; do
  [ "$test_name" = "test_name" ] && continue
  LOG="$LOG_DIR/taie-$test_name.log"
  if [ "$RESUME" = 1 ] && grep -q "Detected" "$LOG" 2>/dev/null; then
    echo "skip $test_name (already done)"
    continue
  fi
  CS6215_ENTRY_CLASS="org.owasp.benchmark.testcode.$test_name" scripts/run_taie.sh \
    --jar taie-release/tai-e-all-0.5.4.jar \
    --cp "$CP" \
    --input-classes "org.owasp.benchmark.testcode.$test_name" \
    --config configs/ \
    --plugin-classes plugin-classes \
    --plugins cs6215.BenchmarkEntryPointPlugin \
    --jre-dir "$JAVA_HOME" \
    --output-dir "$LOG_DIR/taie-$test_name" \
    --heap 4g \
    --pta-opts "reflection-inference:null" > "$LOG" 2>&1
  RAW=$(grep -oE 'Detected [0-9]+' "$LOG" | grep -oE '[0-9]+' || echo "?")
  APP=$(grep 'TaintFlow{' "$LOG" | sed 's/^.*-> //' | grep -c 'org.owasp.benchmark' || true)
  printf '%s\t%s\t%s\n' "$test_name" "$RAW" "$APP" >> "$SUMMARY"
  echo "$test_name: raw=$RAW app=$APP"
  N=$((N + 1))
done < "$CASES_CSV"
echo "done: $N cases, summary in $SUMMARY"
