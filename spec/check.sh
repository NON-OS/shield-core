#!/bin/bash
# The wallet's TLA+ models, checked by TLC. Account and Notes must hold.
# Frozen is the wallet without take-back and must still fail: a model that
# stopped finding that hole would be a model that stopped seeing anything.
set -euo pipefail
cd "$(dirname "$0")"
JAR="${TLA_TOOLS:-tla2tools.jar}"
[ -f "$JAR" ] || curl -sSL -o "$JAR" https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar
echo "32d64fbbc464559fc7192341b27b885fa4eb6b92d1648d2b49fb9cdcb7aacf81  $JAR" | shasum -a 256 -c -
tlc() { java -XX:+UseParallelGC -cp "$JAR" tlc2.TLC -workers auto -config "$1.cfg" "$2.tla" 2>&1; }
for model in Account Notes; do
    out=$(tlc "$model" "$model") || true
    echo "$out" | grep -E "distinct states found" | tail -1
    echo "$out" | grep -q "No error has been found" || { echo "$model: a property failed" >&2; exit 1; }
    echo "$model: every property holds"
done
# TLC exits non-zero when it finds the violation, which is the point here.
frozen=$(tlc Frozen Notes) || true
if echo "$frozen" | grep -q "NothingFrozen was violated"; then
    echo "Frozen: still finds the note a lost hand-off would freeze without take-back"
else
    echo "Frozen: the model no longer finds the hole take-back closes" >&2
    exit 1
fi
