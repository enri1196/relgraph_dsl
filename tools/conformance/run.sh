#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
UPSTREAM="$ROOT/tests/fixtures/openfga/upstream"
ANTLR_JAR="${ANTLR_JAR:-$ROOT/tools/conformance/antlr-4.13.2-complete.jar}"

if [[ ! -f "$ANTLR_JAR" ]]; then
    printf 'ANTLR 4.13.2 jar not found: %s\nSet ANTLR_JAR to its location.\n' "$ANTLR_JAR" >&2
    exit 2
fi
if [[ "$#" -eq 0 ]]; then
    set -- "$ROOT/tests/fixtures/openfga/valid" "$ROOT/tests/fixtures/openfga/invalid"
fi

OUT="$(mktemp -d "${TMPDIR:-/tmp}/openfga-antlr-4.13.2.XXXXXX")"
trap 'rm -rf "$OUT"' EXIT

(
    cd "$UPSTREAM"
    java -jar "$ANTLR_JAR" -Dlanguage=Java -o "$OUT" OpenFGALexer.g4
    java -jar "$ANTLR_JAR" -Dlanguage=Java -lib "$OUT" -o "$OUT" OpenFGAParser.g4
)

javac -cp "$ANTLR_JAR" -d "$OUT" "$OUT"/*.java "$ROOT/tools/conformance/ConformanceRunner.java"
java -cp "$OUT:$ANTLR_JAR" ConformanceRunner "$@"
