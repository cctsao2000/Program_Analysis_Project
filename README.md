# CS6215 Course Project: Symbolic vs. Neuro-Symbolic Taint Analysis

Comparative study of a symbolic static-analysis baseline (Tai-e taint
analysis) against a self-designed neuro-symbolic analyzer (Tai-e
candidate enumeration + LLM adjudication + symbolic grounding
verification) on the same subjects: a stratified sample of the OWASP
BenchmarkJava suite for four injection vulnerabilities (CWE-89 SQL
injection, CWE-79 XSS, CWE-22 path traversal, CWE-78 command
injection).

Course: CS6215 Advanced Topics in Program Analysis, Fall 2026 (NUS).
Report deadline: 30 November 2026, 23:59 SGT. This repository is the
project artifact: it contains the baseline configuration, the
neuro-symbolic solution, evaluation scripts, and the files used to
produce the reported results.

## Design (summary)

- **B0 — baseline:** Tai-e taint analysis with one fixed configuration
  (`configs/taint-config.yml`) for all subjects. Sanitizers are
  deliberately not modelled, so the baseline over-approximates.
- **N1 — main neuro-symbolic solution:** Tai-e enumerates candidate
  taint flows; an LLM adjudicates each flow with the flow facts plus a
  minimal code slice (`prompts/adjudicate.md`); a symbolic grounding
  checker (`src/grounding_check.py`) verifies the LLM's cited sanitizer
  evidence against the slice, and unverifiable `FP` claims fall back
  to the baseline verdict.
- **N0 — ablation:** LLM alone, same slices, no Tai-e flow facts.
- **N2 — ablation:** N1 outputs with the grounding check disabled
  (no extra LLM calls).
- **Optional extension:** feed LLM-identified, human-verified
  sanitizers back into the Tai-e configuration and re-run the baseline.

Evaluation: precision/recall/F1 per CWE and overall
(`scripts/score.py`), FP-reduction vs. TP-loss, abstention and
grounding-failure rates, plus qualitative analysis of representative
successes, failures, and negative results.

## Status (2026-11-18, scaffold + smoke test)

| Item | Status |
|---|---|
| Tai-e runs end-to-end with taint analysis | ✅ Verified on Tai-e's own `SimpleTaint` test program: exactly 6 taint flows, matching the expected output (see `SMOKE_TEST.md`) |
| Tai-e release jar (0.5.4) | ✅ Downloaded and verified; `--jre-dir` avoids the large `java-benchmarks` submodule |
| Taint config draft for 4 CWEs | ✅ Resolved 2026-11-18: entry-point plugin (`src/BenchmarkEntryPointPlugin.java`), call-site mode, servlet-interface sources, JDBC + Spring sinks (59 sources / 120 sinks / 8 transfers + 138 String transfers); validation pending -- see `PILOT.md` |
| Entry-point plugin for servlets | 🟡 Written 2026-11-18, not yet compiled (this VM has no JDK) -- compile on your machine per `PILOT.md` step 1 |
| OWASP BenchmarkJava ground truth | ✅ `data/expectedresults-1.2.csv` copied (2,740 cases); per-CWE counts verified |
| Stratified sampling | ✅ `scripts/sample_cases.py` verified; `data/sample_seed42.csv` (240 cases, 30 vuln + 30 safe per CWE) |
| Scoring | ✅ `scripts/score.py` verified on a hand-checked synthetic example |
| Grounding checker | ✅ `src/grounding_check.py` verified on 3 toy cases (pass / wrong line / no evidence) |
| Tai-e runner wrapper | ✅ `scripts/run_taie.sh` reproduces the smoke test (6 flows); extended 2026-11-18 with `--input-classes`, `--plugin-classes`, `--plugins` and directory `--config` for the servlet pilot |
| LLM adjudication prompt | 🟡 Draft only; never run against a model |
| OWASP BenchmarkJava compile | ❌ Blocked **in the setup VM only**: Java HTTP clients cannot download Maven dependencies through that VM's egress proxy (see `SMOKE_TEST.md`). Compile on a machine with direct internet access. Nothing was compiled yet. |
| Tai-e run on BenchmarkJava | ❌ Not attempted. Blocked on the compile above; the 8-case pilot is specified in `PILOT.md` (1 vuln + 1 safe per CWE). |
| LLM runs / results | ❌ Not started. Needs a SoCLaaS API key (see below). |

## Open questions

1. **Entry points for BenchmarkJava — RESOLVED 2026-11-18
   (validation pending).** `src/BenchmarkEntryPointPlugin.java`
   adds `doGet`/`doPost` of every `HttpServlet` subclass in the
   world as entry points, loaded via `pta=...;plugins:[...]` with
   no Tai-e source build. Key trap found in Tai-e's sources:
   `DeclaredParamProvider` skips interface types, so the plugin
   uses `SpecifiedParamProvider` with explicit mock objects; and
   `call-site-mode: true` is required because dispatch on the
   interface-typed mocks finds no callee. See `PILOT.md`.
2. **Servlet-interface sources — RESOLVED 2026-11-18
   (validation pending).** Exact `HttpServletRequest` /
   `ServletRequest` entries added to `configs/taint-config.yml`.
   Known gap: `getParameterValues()[0]` and
   `getParameterMap().get()[0]` extraction do not propagate taint
   (18/120 sampled vulnerable cases; 14 more iterate
   `getParameterNames()` but take `param` from `nextElement()` and
   are covered); candidate stub fix in `PILOT.md` §6.
3. **SQL sinks — RESOLVED 2026-11-18 (validation pending).**
   `java.sql.Statement` execute family + `addBatch`,
   `Connection.prepareStatement/prepareCall` overloads, and Spring
   `JdbcTemplate` `queryFor*`/`batchUpdate`/`execute` added.
   Design decision recorded in `configs/taint-config.yml`: the
   sink for prepared statements is the *prepare* call (tainted SQL
   string), not the no-arg execute.
4. **Model selection.** Record the exact SoCLaaS model ID and confirm
   it follows the strict JSON output format on 5 pilot cases before
   the scored batch.

## Repository layout

```text
README.md                  This file
SMOKE_TEST.md              Dated setup/smoke-test log with evidence
configs/
  taint-config.yml         Draft Tai-e taint configuration (see TODOs)
prompts/
  adjudicate.md            LLM adjudication prompt + JSON schema + checklists
scripts/
  run_taie.sh              Tai-e runner wrapper (verified on the smoke test)
  sample_cases.py          Stratified sampling from ground truth (verified)
  score.py                 Precision/recall/F1 scoring (verified)
src/
  grounding_check.py       Symbolic grounding checker (verified on toy cases)
examples/
  toy_slice.java           Toy slice for the grounding checker
  toy_judgement_*.json     Toy LLM judgements (pass / fail / no evidence)
data/
  expectedresults-1.2.csv  OWASP BenchmarkJava v1.2 ground truth (2,740 cases)
  sample_seed42.csv        Stratified sample: 240 cases (seed 42)
  example_predictions.csv  Synthetic predictions for the scoring example
results/                   (TODO) Raw LLM outputs and scored results
```

Tai-e itself and the BenchmarkJava sources are **not** copied into
this repository. Fetch them as described below.

## Prerequisites

- JDK 17+ and Maven 3.8+ (for the BenchmarkJava build).
- Python 3.10+ (standard library only; no third-party packages).
- A SoCLaaS API key for the LLM runs (see "LLM access").

## Setup (commands verified 2026-11-18 on Ubuntu 24.04)

```bash
# 1. JDK 17 + Maven (apt; versions observed: OpenJDK 17.0.21, Maven 3.8.7)
sudo apt-get update
sudo apt-get install -y openjdk-17-jdk maven
java -version && mvn -version

# 2. Tai-e 0.5.4 release jar (README-recommended way to obtain runnable Tai-e)
mkdir -p ../cs6215-work/taie-release && cd ../cs6215-work/taie-release
curl -sL -o tai-e-all-0.5.4.jar \
  https://github.com/pascal-lab/Tai-e/releases/download/v0.5.4/tai-e-all-0.5.4.jar
java -jar tai-e-all-0.5.4.jar -h   # should print Tai-e usage

# 3. Tai-e sources (for configuration reference and docs; shallow, no submodules)
cd ../cs6215-work
git clone --depth 1 --no-recurse-submodules https://github.com/pascal-lab/Tai-e taie

# 4. OWASP BenchmarkJava (ground truth + subjects)
git clone --depth 1 https://github.com/OWASP-Benchmark/BenchmarkJava benchmarkjava
```

Notes:

- Building Tai-e from source with the Gradle wrapper was **not**
  verified in the setup VM (Gradle daemon IPC failed in that sandbox;
  see `SMOKE_TEST.md`). The release jar is the pinned baseline
  artifact for this project; building from source on a normal machine
  should follow Tai-e's README (`./gradlew fatJar`).
- The large `java-benchmarks` submodule is **not** needed when Tai-e is
  given `--jre-dir <JDK>` (verified). `scripts/run_taie.sh` does this.
- `mvn compile` of BenchmarkJava must run on a machine with direct
  internet access (see Status). The project targets Java 8
  (`<java.target>8</java.target>` in its `pom.xml`), which JDK 17
  supports via `--release 8`.

## Reproduction steps

```bash
# 0. Verify the scaffold pieces (no Java / network needed)
python3 scripts/sample_cases.py --csv data/expectedresults-1.2.csv \
    --cwes 89,79,22,78 --per-cwe 60 --seed 42 --output /tmp/sample-check.csv
python3 scripts/score.py --predictions data/example_predictions.csv \
    --ground-truth data/expectedresults-1.2.csv --cases data/example_predictions.csv
python3 src/grounding_check.py --slice examples/toy_slice.java \
    --judgement examples/toy_judgement_fp_pass.json --baseline flagged

# 1. TODO: compile BenchmarkJava (direct internet required)
cd ../cs6215-work/benchmarkjava && mvn -B -DskipTests compile

# 2. TODO: run the 8-case pilot first (PILOT.md), then the full
#    240-case sample. One test class per run; the entry-point plugin
#    supplies doGet/doPost, so no --main is needed.
javac -cp ../cs6215-work/taie-release/tai-e-all-0.5.4.jar \
    -d plugin-classes src/BenchmarkEntryPointPlugin.java
scripts/run_taie.sh --jar ../cs6215-work/taie-release/tai-e-all-0.5.4.jar \
    --cp <compiled-classes-and-deps> \
    --input-classes org.owasp.benchmark.testcode.BenchmarkTest00438 \
    --config configs/ --plugin-classes plugin-classes \
    --plugins cs6215.BenchmarkEntryPointPlugin \
    --jre-dir "$JAVA_HOME" --output-dir output/taie-pilot-00438

# 3. TODO: build slices, run LLM adjudication (see prompts/adjudicate.md),
#    apply src/grounding_check.py, score with scripts/score.py.
```

Steps 1-3 are **not yet verified**; do not treat them as working
until the open questions are resolved and the runs are logged here.

## LLM access

The LLM harness (TODO) must read its key **only** from the
`SOCLAAS_API_KEY` environment variable. Never write a key into any
file in this repository. SoCLaaS details:

- Portal (key creation; requires the NUS network or VPN):
  <https://soclaas-portal.comp.nus.edu.sg>
- API base URL (OpenAI-compatible):
  `https://soclaas-api.comp.nus.edu.sg/v1`
- List available models with `GET /v1/models` using the key; record
  the exact model ID used for every scored run.

## Data provenance

- `data/expectedresults-1.2.csv`: copied verbatim from the
  OWASP-Benchmark/BenchmarkJava repository (v1.2 ground truth).
  Per-CWE counts verified 2026-11-18: CWE-89: 272 vuln / 232 safe;
  CWE-79: 246 / 209; CWE-22: 133 / 135; CWE-78: 126 / 125.
- `data/sample_seed42.csv`: generated by `scripts/sample_cases.py`
  (seed 42, 60 per CWE, balanced). Regenerating with the same seed
  reproduces the file exactly.

## Citation

Tai-e: Tian Tan and Yue Li. "Tai-e: A Developer-Friendly Static
Analysis Framework for Java by Harnessing the Good Designs of
Classics." ISSTA 2023. <https://github.com/pascal-lab/Tai-e>
