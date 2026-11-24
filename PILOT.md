# CS6215 pilot: first Tai-e runs on OWASP BenchmarkJava

Date: 2026-11-18. Status: the three open questions from README.md
(entry points, servlet-interface sources, SQL sinks) are resolved
from Tai-e's own sources -- see "Evidence trail" below. Nothing here
has been executed yet: this VM has no JDK and no Maven access, so the
pilot runs on your own machine (direct internet), tonight before the
Taipei flight if possible -- the three user-only tasks from last
night (SoCLaaS key, first commit, `mvn compile`) are prerequisites
for steps 0-1 below anyway.

## 0. Prerequisites (your machine)

```bash
# JDK 17 + Maven; BenchmarkJava compiled (needs direct internet)
cd ../cs6215-work/benchmarkjava && mvn -B -DskipTests compile
# Tai-e 0.5.4 release jar, if not already there (see README.md setup)
ls ../cs6215-work/taie-release/tai-e-all-0.5.4.jar
```

## 1. Compile the entry-point plugin (no Tai-e source build needed)

```bash
cd workspace/cs6215-project
javac -cp ../cs6215-work/taie-release/tai-e-all-0.5.4.jar \
    -d plugin-classes src/BenchmarkEntryPointPlugin.java
```

## 2. Build the classpath for the benchmark run

```bash
cd ../cs6215-work/benchmarkjava
mvn -B dependency:build-classpath -Dmdep.outputFile=/tmp/bench-cp.txt
# then, per case (from workspace/cs6215-project):
CP="target/classes:$(cat /tmp/bench-cp.txt)"
```

## 3. Run one pilot case

```bash
cd workspace/cs6215-project
scripts/run_taie.sh \
  --jar ../cs6215-work/taie-release/tai-e-all-0.5.4.jar \
  --cp "$CP" \
  --input-classes org.owasp.benchmark.testcode.BenchmarkTest00438 \
  --config configs/ \
  --plugin-classes plugin-classes \
  --plugins cs6215.BenchmarkEntryPointPlugin \
  --jre-dir "$JAVA_HOME" \
  --output-dir output/taie-pilot-00438
```

Notes:

- `--config configs/` (a directory) loads both `taint-config.yml`
  and `taint-string-transfers.yml`; Tai-e merges them.
- Each run analyses exactly one test class (`--input-classes`
  scopes the world; the plugin adds `doGet`/`doPost` of every
  `HttpServlet` subclass in the world as entry points). Expect
  minutes per case (the tiny smoke test took ~52 s; a benchmark
  case pulls in the JDK + servlet + Spring jars).
- Tai-e prints `Detected N taint flow(s):` on stdout and logs the
  loaded `TaintConfig` at startup -- check the log line contains
  `callSiteMode: true`. If the plugin class is not found you get
  `Plugin class cs6215.BenchmarkEntryPointPlugin is not found`
  immediately; that means the `-cp` launcher path was not used.

## 4. The 8 pilot cases (1 vulnerable + 1 safe per CWE)

Ground truth is `data/expectedresults-1.2.csv`. Each case was picked
from `data/sample_seed42.csv` so its source and sink shapes exercise
the newly resolved config (see the "validates" column).

| Case | CWE | Truth | Validates |
|---|---|---|---|
| BenchmarkTest00438 | 89 SQLi | vuln | `Statement.execute(String, String[])` sink (new overload); `getParameter` source |
| BenchmarkTest01878 | 89 SQLi | safe | `Connection.prepareStatement(String, int)` sink must NOT fire: `bar` is a constant inside `doSomething`, so the SQL string is untainted; no-arg `execute()` is correctly not a sink |
| BenchmarkTest01057 | 79 XSS | vuln | `getHeader` source; `PrintWriter` sink via `response.getWriter()` |
| BenchmarkTest02135 | 79 XSS | safe | `getParameter` source with a safe (sanitised/constant) flow; expect 0 flows |
| BenchmarkTest02112 | 22 path traversal | vuln | `FileOutputStream(String, boolean)` sink, index 1 |
| BenchmarkTest01237 | 22 path traversal | safe | `new File(String)` sink with a safe flow; expect 0 flows |
| BenchmarkTest00407 | 78 command injection | vuln | `Runtime.exec(String, String[])` sink, index 0 |
| BenchmarkTest00411 | 78 command injection | safe | same sink shape, safe flow; expect 0 flows |

Pass bar for the pilot: all 4 vulnerable cases report >= 1 flow,
all 4 safe cases report 0. A flow on a safe case is not
automatically a config error -- it may be a genuine baseline false
positive (the over-approximating baseline is *supposed* to produce
some; the LLM adjudicator's job is to clear them). Record each one
with its flow and decide from the flow, don't silently tweak the
config to make the pilot green.

## 5. If a vulnerable case reports zero flows

Check in this order:

1. The startup log shows `callSiteMode: true`. If not, the config
   directory was not loaded (wrong `--config` path).
2. The plugin loaded (no "is not found" error) and the run's
   reachable methods include the test class's `doGet`/`doPost`.
   Without the plugin there are no entry points at all.
3. The source shape of that case: if it extracts input only via
   `getParameterValues()[0]` or `getParameterMap().get()[0]`, see
   "Known gap" below -- that is the expected blind spot, not a
   setup error.

## 6. Known gap (measured, not guessed)

In the 240-case sample, 18 of the 120 vulnerable cases extract
input *only* through `getParameterValues()[0]` or
`getParameterMap().get()[0]` (counted by tracing which value is
assigned to `param`, not by file-level keyword matches: all 18
assign `param = values[0]`). Those shapes do not propagate taint
in this configuration: the source call is unresolved (its receiver
is an interface-typed mock object, on which Tai-e's dispatch finds
no callee), so the result variable never holds a real array/Map
object for the ARRAY-kind source or the `Map.get` transfer to
attach taint to. `getParameterNames()` *is* covered, via the
`Enumeration.nextElement()` transfer (a VAR->VAR transfer, which
needs no resolved call edge): 14 further cases iterate
`getParameterNames()` alongside a `getParameterValues` call but
take the sink-reaching value from `nextElement()` (`param = name`),
so they are covered and are not counted in the 18. The other 88
vulnerable cases use
`getParameter`/`getHeader`/`getCookies` or the
`SeparateClassRequest` helper (whose own `getParameter` call is
reachable and fires in call-site mode).

Candidate fix for round 2 (not built yet -- it needs a machine
with a JDK to compile and test): a concrete stub
`HttpServletRequest` implementation whose `getParameterValues()`
returns a real `String[1]` and whose `getParameterMap()` returns
a pre-loaded `Map`, with the plugin supplying mock objects of the
stub type instead of the interface type, so dispatch resolves and
the array/Map objects exist. Do not count these 18 cases as true
negatives until that is validated.

## Evidence trail (all checked 2026-11-18 in the Tai-e checkout)

- Entry points: `EntryPointHandler` only adds `main` + JVM
  implicit entries; `pta` option `plugins:[...]` loads a plugin
  class via `Class.forName` (`PointerAnalysis.addPlugins`), so a
  plugin compiled against the release jar works without building
  Tai-e from source.
- `DeclaredParamProvider` skips abstract/interface types
  (`isInstantiable`), so the plugin must use
  `SpecifiedParamProvider.Builder` + explicit `getMockObj` calls
  (modelled on Tai-e's own `CustomEntryPointPlugin` test).
- Call-site mode: YAML key `call-site-mode`
  (`YamlTaintConfigProvider`); in this mode `SourceHandler`,
  `SinkHandler` and `TransferHandler` fire from the method
  reference at the call site in a reachable method, with no
  resolved call edge needed. Multiple config files: pass a
  directory as `taint-config` (taint-analysis reference,
  "Multiple Configuration Files").
- Interface sources: `SignatureMatcher.getMethods` resolves an
  exact interface signature to the interface method; BenchmarkJava
  calls `request.getParameter/getHeader/getCookies` on the
  interface type (2,071 files).
- SQL sinks: measured usage in the 60 sampled CWE-89 cases --
  `prepareStatement` 14, `prepareCall` 8, no-arg `executeQuery()`
  8, `execute(sql, ...)` 10, `executeQuery(sql)` 1,
  `executeUpdate(sql)` 4, `addBatch(sql)` 4; Spring
  `JdbcTemplate` across all 2,740 files -- `queryForObject` 52,
  `batchUpdate` 39, `queryForLong` 27, `queryForList` 19,
  `query` 16, `queryForMap` 15, `queryForRowSet` 15,
  `execute` 16. Tai-e's bundled Spring file covers none of the
  `queryFor*`/`batchUpdate` methods.
- `PreparedStatement` design decision: sink at the prepare call,
  not at no-arg execute; see the comment in
  `configs/taint-config.yml`.
