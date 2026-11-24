#!/usr/bin/env bash
# Run Tai-e taint analysis with a pinned configuration.
#
# This wrapper reproduces the exact command verified in the smoke test
# (see SMOKE_TEST.md, 2026-11-18): Tai-e 0.5.4 release jar, context-
# insensitive pointer analysis (the default), one taint-config file,
# JRE classes supplied via --jre-dir so the large `java-benchmarks`
# submodule is NOT needed.
#
# Usage:
#   scripts/run_taie.sh --jar <tai-e-all-*.jar> --cp <classes-dir-or-jar> \
#       [--main <main-class>] [--input-classes <class,...>] \
#       --config configs/taint-config.yml \
#       [--java-version 17] [--jre-dir "$JAVA_HOME"] \
#       [--output-dir output/taie-run1] [--heap 1g] [--pta-opts "cs:1-obj"]
#
# Servlet / plugin mode (OWASP BenchmarkJava, see PILOT.md):
#   scripts/run_taie.sh --jar <tai-e-all-*.jar> \
#       --cp <benchmark-classes>:<deps> \
#       --input-classes org.owasp.benchmark.testcode.BenchmarkTest00001 \
#       --config configs/ \
#       --plugin-classes plugin-classes \
#       --plugins cs6215.BenchmarkEntryPointPlugin \
#       --jre-dir "$JAVA_HOME" --output-dir output/taie-pilot-00001
#   --plugin-classes switches the launcher from `java -jar` to
#   `java -cp <jar>:<plugin-classes> pascal.taie.Main`, because
#   `java -jar` ignores -cp and Tai-e loads plugin classes with
#   Class.forName. --config accepts a file or a directory (a directory
#   loads every taint-config file in it; configs/ holds
#   taint-config.yml plus taint-string-transfers.yml).
#
# Notes:
# - --jre-dir defaults to $JAVA_HOME; it must point at a JDK directory
#   whose lib/ contains the Java 9+ module image (lib/modules).
# - --main may be omitted when --input-classes + --plugins supply the
#   entry points (the servlet plugin adds doGet/doPost). For programs
#   without a main() method and without the plugin, Tai-e has no entry
#   points -- see README.md "Open questions" (now resolved; PILOT.md).
# - Extra pointer-analysis options go in --pta-opts and are appended
#   to the pta= option list (e.g. "cs:1-obj"). The default is Tai-e's
#   default context-insensitive analysis, exactly as smoke-tested.
set -euo pipefail

JAR=""
CP=""
MAIN_CLASS=""
INPUT_CLASSES=""
CONFIG=""
PLUGIN_CLASSES=""
PLUGINS=""
JAVA_VERSION="17"
JRE_DIR="${JAVA_HOME:-}"
OUTPUT_DIR=""
HEAP="1g"
PTA_OPTS=""

usage() {
  sed -n '2,41p' "$0"
  exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --jar) JAR="$2"; shift 2 ;;
    --cp) CP="$2"; shift 2 ;;
    --main) MAIN_CLASS="$2"; shift 2 ;;
    --input-classes) INPUT_CLASSES="$2"; shift 2 ;;
    --config) CONFIG="$2"; shift 2 ;;
    --plugin-classes) PLUGIN_CLASSES="$2"; shift 2 ;;
    --plugins) PLUGINS="$2"; shift 2 ;;
    --java-version) JAVA_VERSION="$2"; shift 2 ;;
    --jre-dir) JRE_DIR="$2"; shift 2 ;;
    --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
    --heap) HEAP="$2"; shift 2 ;;
    --pta-opts) PTA_OPTS="$2"; shift 2 ;;
    -h|--help) usage 0 ;;
    *) echo "unknown argument: $1" >&2; usage 2 ;;
  esac
done

[[ -n "$JAR" ]] || { echo "error: --jar is required" >&2; usage 2; }
[[ -n "$CP" ]] || { echo "error: --cp is required" >&2; usage 2; }
[[ -n "$CONFIG" ]] || { echo "error: --config is required" >&2; usage 2; }
[[ -f "$JAR" ]] || { echo "error: jar not found: $JAR" >&2; exit 1; }
[[ -e "$CONFIG" ]] || { echo "error: taint config not found: $CONFIG" >&2; exit 1; }
[[ -n "$JRE_DIR" ]] || { echo "error: --jre-dir or JAVA_HOME is required" >&2; exit 1; }
[[ -d "$JRE_DIR/lib" ]] || { echo "error: JRE dir has no lib/: $JRE_DIR" >&2; exit 1; }
if [[ -z "$OUTPUT_DIR" ]]; then
  OUTPUT_DIR="output/taie-$(date +%Y%m%d-%H%M%S)"
fi

PTA="taint-config:${CONFIG}"
if [[ -n "$PLUGINS" ]]; then
  PTA="${PTA};plugins:[${PLUGINS}]"
fi
if [[ -n "$PTA_OPTS" ]]; then
  PTA="${PTA_OPTS};${PTA}"
fi

if [[ -n "$PLUGIN_CLASSES" ]]; then
  # Plugin mode: plugins load via Class.forName, so the plugin classes
  # must be on the JVM classpath -- `java -jar` ignores -cp.
  CMD=(java "-Xmx${HEAP}" -cp "${JAR}:${PLUGIN_CLASSES}" pascal.taie.Main -cp "$CP")
else
  CMD=(java "-Xmx${HEAP}" -jar "$JAR" -cp "$CP")
fi
if [[ -n "$MAIN_CLASS" ]]; then
  CMD+=(-m "$MAIN_CLASS")
fi
if [[ -n "$INPUT_CLASSES" ]]; then
  CMD+=(--input-classes "$INPUT_CLASSES")
fi
CMD+=(-java "$JAVA_VERSION" --jre-dir "$JRE_DIR" -a "pta=${PTA}" --output-dir "$OUTPUT_DIR")

echo "+ ${CMD[*]}"
exec "${CMD[@]}"
