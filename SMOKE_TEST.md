# Smoke-test log — 2026-11-18

Setup + smoke test for the CS6215 course project (Plan A: Tai-e taint
analysis baseline + LLM adjudication with grounding verification).
All work below was done in the setup VM (Ubuntu 24.04, 4 vCPUs visible,
~6 GB cgroup limit). Times are SGT (UTC+8) unless noted. No API keys
were used, requested, or stored; no LLM calls were made.

## Environment (as found)

- OS: Ubuntu 24.04.5 LTS. Shell user: root; home `/home/hatch`.
- `java`: NOT installed. `mvn`: NOT installed.
- Python 3.12.3, git 2.43.0, curl/wget/tar/unzip present.
- Disk: ~149 GB free. Note: the JVM's `user.home` resolved to `/root`
  (not `$HOME`), so Gradle/Maven caches landed under `/root/.gradle`
  and `/root/.m2`.

## Task 1 — Java toolchain ✅

```bash
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y openjdk-17-jdk maven
```

- Result: exit 0 (~98 s total). No tarball fallback needed.
- `java -version`: openjdk 17.0.21.0.3 (build 17.0.21.0.3+1-1-24.04.1-Ubuntu).
- `mvn -version`: Apache Maven 3.8.7, Maven home `/usr/share/maven`,
  runtime `/usr/lib/jvm/java-17-openjdk-amd64`.
- JDK path: `/usr/lib/jvm/java-17-openjdk-amd64`
  (`lib/modules` and `lib/jrt-fs.jar` both present — needed by Tai-e).

## Task 2 — Tai-e smoke test ✅ (via release jar; source build blocked)

### Clones

```bash
git clone --depth 1 --no-recurse-submodules https://github.com/pascal-lab/Tai-e taie
git clone --depth 1 https://github.com/OWASP-Benchmark/BenchmarkJava benchmarkjava
```

- Tai-e: 29.5 s, 19 MB. HEAD `407994d1efae8d31d844791057bb071b43693438`
  ("Drop lambda call edges whose arguments do not fit the target").
  `gradle.properties` says version `0.5.5-SNAPSHOT`. Submodule
  directories `java-benchmarks/` and `android-benchmarks/` are empty
  (not fetched).
- BenchmarkJava: 20.8 s, 239 MB.

### Attempt A: Gradle wrapper build — FAILED (environment)

```bash
./gradlew fatJar --no-daemon --max-workers=2
```

- Failure: the wrapper could not download Gradle 9.8.2; the JVM's
  HTTPS download failed with an SSL error
  (`SSLSocketInputRecord.handleUnknownRecord`) because Java does not
  pick up the VM's egress-proxy settings from environment variables.
- Fix attempt: pass proxy host/port/user/password as
  `-Dhttps.proxyHost/...` JVM properties. The wrapper then reached the
  proxy but failed in `HttpURLConnection.doTunneling0` with
  `java.util.NoSuchElementException` (see "Root cause" below).

### Attempt B: standalone Gradle 9.8.2 — FAILED (environment)

- Downloaded `gradle-9.8.2-bin.zip` (151,620,138 bytes) via curl;
  SHA-256 `21bd5da2de49b642904077f38c0efdc7778e92b3ed0889392dca61b97e389607`
  matched the published checksum. `gradle --version` works.
- Build failed before any compilation: `Could not dispatch a message
  to the daemon`, caused by `java.io.IOException: Connection reset by
  peer` writing to the daemon's loopback socket. Daemon logs
  (`/root/.gradle/daemon/9.8.2/daemon-*.out.log`) show the daemon
  starting and then `stop() called on daemon ... terminated in
  response to a user interrupt`. Loopback TCP itself works (a Python
  HTTP server on 127.0.0.1 answered curl with HTTP 200), so the
  failure is specific to Gradle's forked daemon JVM in this sandbox.
  `--no-daemon` did not help: Gradle 9.8.2 still forks a single-use
  daemon ("To honour the JVM settings for this build a single-use
  Daemon process will be forked") and fails the same way.
- No further Gradle attempts were made (time-boxed). Building Tai-e
  from source on a normal machine should follow its README; it was
  not verified here.

### Attempt C: official release jar — ✅ SUCCESS

Tai-e's README recommends the distribution release as the way to
obtain runnable Tai-e. Latest release: `v0.5.4`.

```bash
curl -sL -o tai-e-all-0.5.4.jar \
  https://github.com/pascal-lab/Tai-e/releases/download/v0.5.4/tai-e-all-0.5.4.jar
java -jar tai-e-all-0.5.4.jar -h   # prints Tai-e usage, exit 0
```

Jar size 31,375,637 bytes. Tai-e reports version 0.5.4, commit
`6474e7da62fb1f3b692331040e66692cbf4d630d`.

### Smallest taint example

Tai-e's own test case `SimpleTaint` (+ `SourceSink`, `Sanitizer`) from
`src/test/resources/pta/taint/`, with its example config
`taint-config.yml`, compiled with `javac` (JDK 17, default settings):

```bash
javac -d /tmp/taint-smoke/classes src/test/resources/pta/taint/SimpleTaint.java \
    src/test/resources/pta/taint/SourceSink.java src/test/resources/pta/taint/Sanitizer.java
```

Run 1 (without `--jre-dir`) failed in 1.5 s:

```text
Caused by: java.io.IOException: Failed to locate Java library.
Please clone submodule 'java-benchmarks' by command:
git submodule update --init --recursive
and put it in Tai-e's working directory.
```

Run 2 (with `--jre-dir`, the fix) succeeded. Exact command:

```bash
java -Xmx1g -jar tai-e-all-0.5.4.jar -cp /tmp/taint-smoke/classes \
    -m SimpleTaint -java 17 --jre-dir /usr/lib/jvm/java-17-openjdk-amd64 \
    -a "pta=taint-config:/tmp/taint-smoke/taint-config.yml" \
    --output-dir /tmp/taint-smoke/output2
```

- Exit 0. Wall time 51.6 s, peak memory 819 MB (mostly world-building
  over the JDK 17 library; the test program itself is 3 tiny classes).
- Output: `Detected 6 taint flow(s):`, listing the same 6 source→sink
  pairs as Tai-e's expected output file
  (`SimpleTaint-pta-expected.txt`), including the two flows into
  `sink(s3, 0)` and the field-source flows. The sanitized values
  (`s7`, `s8`) correctly produced no flows.
- The `--jre-dir` flag means the large `java-benchmarks` submodule is
  NOT required. This is the configuration baked into
  `scripts/run_taie.sh`, which was verified to reproduce the run
  (6 flows, 53.4 s, peak 799 MB).

### What the smoke test does and does not prove

- Proves: Tai-e 0.5.4 runs end-to-end on this toolchain; taint
  analysis with a YAML config detects flows and honours sanitizers;
  the runner wrapper is correct.
- Does NOT prove: that the draft `configs/taint-config.yml` works on
  BenchmarkJava (never run), or how entry points should be set for
  servlet subjects (open question; see README.md).

## Task 3 — OWASP Benchmark check 🟡 (ground truth verified; compile blocked)

### Ground truth ✅

- `expectedresults-1.2.csv` exists (95,328 bytes, 2,741 lines = 1 `#`
  comment header + 2,740 cases). Test sources: 2,740 files under
  `src/main/java/org/owasp/benchmark/testcode/`.
- Verified counts (vulnerable `true` / safe `false`):
  - CWE-89 (sqli): 272 / 232 (504)
  - CWE-79 (xss): 246 / 209 (455)
  - CWE-22 (pathtraver): 133 / 135 (268)
  - CWE-78 (cmdi): 126 / 125 (251)
  - Others: CWE-327: 130/116, CWE-328: 129/107, CWE-330: 218/275,
    CWE-501: 83/43, CWE-614: 36/31, CWE-643: 15/20, CWE-90: 27/32.
- `pom.xml`: compiler plugin 3.16.0 with
  `<release>${java.target}</release>`, `<java.target>8</java.target>`
  (supported by JDK 17). The project uses `javax.servlet` (not
  `jakarta`); 2,071 test files call `request.getParameter`,
  `getHeader`, or `getCookies`.
- A copy of the ground-truth CSV is committed in this repo as
  `data/expectedresults-1.2.csv` (provenance in README.md).

### Compile ❌ blocked in this VM (environment, not the project)

```bash
mvn -B -DskipTests compile
```

Every attempt failed within ~3 s at the very first dependency
download (the `.mvn/extensions.xml` build-time extension POM),
before any compilation:

```text
[ERROR] Extension co.leantechniques:maven-buildtime-extension:3.0.5 or one of
its dependencies could not be resolved ...
[ERROR] Caused by: Could not transfer artifact ... from/to central
(https://repo.maven.apache.org/maven2): ... Connection reset
```

Tried, all with the same failure point:

1. Maven 3.8.7 (apt) with a transient `settings.xml` proxy entry
   (host/port/credentials from the environment; file deleted after).
   Maven logged the proxy with `userName='null'`.
2. Maven 3.9.11 (tarball from archive.apache.org, verified working
   `mvn -version`) with the same settings approach.
3. Maven 3.9.11 through a local unauthenticated CONNECT forward-proxy
   (temporary Python script, since removed) that adds the upstream
   proxy authorization. `curl` through that proxy fetched the same
   POM with HTTP 200; Maven still got `Connection reset`.

No `target/` directory was produced; zero classes compiled. The
blocker is environmental (see "Root cause") and is expected NOT to
apply on a machine with direct internet access (e.g. Amber's own
machine or an NUS host). Recommended next step: run `mvn compile`
there; do not sink more time into this VM's proxy.

### Root cause (Java HTTPS through this VM's egress proxy)

A minimal Java program using `HttpsURLConnection` through a proxy
reproduces the same failure class as the Gradle wrapper:

```text
Exception in thread "main" java.lang.RuntimeException:
  java.util.NoSuchElementException
    at ...HttpURLConnection.getInputStream0(...)
    at ...HttpURLConnection.doTunneling0(...)
```

while `curl` and `git` (which honour the proxy environment variables
and send proxy credentials preemptively) work fine through the same
proxy. Conclusion: Java HTTP clients (Gradle wrapper, Maven's HTTP
transports, `HttpsURLConnection`) cannot complete HTTPS requests via
this VM's egress proxy. All download-dependent Java builds are
therefore blocked here; the Tai-e smoke test succeeded precisely
because it needed no downloads (release jar + local JDK).

## Task 4 — Scaffold verification ✅

All scaffold pieces were executed (see README.md for layout):

- `scripts/sample_cases.py --csv data/expectedresults-1.2.csv
  --cwes 89,79,22,78 --per-cwe 60 --seed 42` → 240 cases, 30
  vulnerable + 30 safe per CWE; output `data/sample_seed42.csv`.
- `scripts/score.py` on `data/example_predictions.csv` (8 hand-built
  rows) → overall P 0.6000 / R 0.7500 / F1 0.6667; CWE-22
  0.5/0.5/0.5; CWE-89 0.6667/1.0/0.8 — matches hand computation.
- `src/grounding_check.py` on the toy slice: evidence on the correct
  line → `cleared`/`pass`; evidence on a wrong line → `flagged`/
  `failed` (conservative fallback); no evidence → `flagged`/
  `no_evidence`.
- `configs/taint-config.yml`: all 108 uncommented method entries
  verified to appear verbatim in Tai-e's bundled config/test files;
  YAML parses (32 sources, 83 sinks, 7 transfers). SQL sinks and
  servlet-interface sources remain commented TODOs (see the file).
- `scripts/run_taie.sh`: reproduces the smoke test (6 flows).

## Versions pinned for the report

- Tai-e baseline artifact: release `0.5.4` jar, commit
  `6474e7da62fb1f3b692331040e66692cbf4d630d`.
- Tai-e sources consulted (configs/docs): commit
  `407994d1efae8d31d844791057bb071b43693438` (0.5.5-SNAPSHOT).
- JDK: OpenJDK 17.0.21.0.3. Maven (apt): 3.8.7.
- OWASP BenchmarkJava: shallow clone of master, 2026-11-18;
  ground truth `expectedresults-1.2.csv` (Benchmark v1.2).
- Pointer-analysis options for the smoke test: Tai-e defaults
  (context-insensitive) + `taint-config:<test config>`.
