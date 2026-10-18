# Pinned ANTLR conformance runner

This maintainer-only runner generates and executes the OpenFGA DSL grammar at
`openfga/language` revision
`fbc62984d02fc8ff7e2a924e0b9c34193233007c`. It uses ANTLR **4.13.2** and
Java **17**. It is not a Cargo build or test dependency and does not download
anything at runtime.

## Pinned source files

The grammar and its upstream license are vendored in
`relgraph-dsl/tests/fixtures/openfga/upstream/` from:

- <https://github.com/openfga/language/blob/fbc62984d02fc8ff7e2a924e0b9c34193233007c/OpenFGALexer.g4>
- <https://github.com/openfga/language/blob/fbc62984d02fc8ff7e2a924e0b9c34193233007c/OpenFGAParser.g4>
- <https://github.com/openfga/language/blob/fbc62984d02fc8ff7e2a924e0b9c34193233007c/LICENSE>

SHA-256 checksums (lowercase hex):

```text
62baac1aacce61e5ee3df09dd281d230ce755addd34abbe36e82fadd29f2a855  OpenFGALexer.g4
7dd561774502881fe594da45e61f1b0ac123910d6f883e12462a2c9f98d0d83f  OpenFGAParser.g4
cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30  LICENSE
```

## Run

Obtain the ANTLR complete jar from the official release URL, then set
`ANTLR_JAR` to that jar's path:

```sh
curl -L https://www.antlr.org/download/antlr-4.13.2-complete.jar -o /tmp/antlr-4.13.2-complete.jar
shasum -a 256 /tmp/antlr-4.13.2-complete.jar
ANTLR_JAR=/tmp/antlr-4.13.2-complete.jar bash tools/conformance/run.sh
```

The ANTLR 4.13.2 complete jar used for the Task 1 runner check has SHA-256
`eae2dfa119a64327444672aff63e9ec35a20180dc5b8090b7a6ab85125df4d76`.

## Task 10 differential audit

The Task 10 run used Homebrew OpenJDK `17.0.20.1` and the ANTLR jar above
(SHA-256 verified immediately before execution). Exact invocation:

```sh
PATH=/opt/homebrew/opt/openjdk@17/bin:$PATH ANTLR_JAR=/private/tmp/antlr-4.13.2-complete.jar bash tools/conformance/run.sh > relgraph-dsl/tests/fixtures/openfga/upstream-results.jsonl
```

The runner generated the lexer and parser, compiled the Java runner, and
executed all 64 syntax fixtures. Results contain 26 accepted fixtures and 38
rejected fixtures; acceptance matched every paired metadata record. The
generated classes and downloaded jar remained in temporary directories and
are not Cargo dependencies.

The runner checks the bare grammar. Since plan Task 12, Relgraph strips `#`
comments as the OpenFGA tooling does, so two fixtures (`hash-inside-rewrite`,
`trailing-hash-prose`) are in `valid/` with `"grammar_parse": "reject"` in
their metadata; `cargo test -p relgraph_dsl --test conformance` checks the
recorded results against that field. The 2026-10-18 rerun for that change used
the same JDK and jar and produced the same 26 accepted / 38 rejected results.

The runner creates a clean temporary generation directory on each invocation.
The exact generation and compile steps used by `run.sh` are:

```sh
java -jar "$ANTLR_JAR" -Dlanguage=Java -o "$OUT" OpenFGALexer.g4
java -jar "$ANTLR_JAR" -Dlanguage=Java -lib "$OUT" -o "$OUT" OpenFGAParser.g4
javac -cp "$ANTLR_JAR" -d "$OUT" "$OUT"/*.java tools/conformance/ConformanceRunner.java
java -cp "$OUT:$ANTLR_JAR" ConformanceRunner relgraph-dsl/tests/fixtures/openfga/valid relgraph-dsl/tests/fixtures/openfga/invalid
```

The commands run from the vendored grammar directory for generation and from
the repository root for compilation/execution. The runner installs error
listeners on both lexer and parser, invokes the parser's `main` rule, and emits
one JSON Lines record per `.fga` fixture in sorted path order, with the fixture
ID, zero-diagnostic acceptance, and total diagnostic count. No ANTLR diagnostic
wording or parse-tree serialization is treated as stable output.
