#!/usr/bin/env bash
# Translate the verified crate into Lean, through Charon and Aeneas.
#
# The proofs in lean-verified/ are about the code in verified/, not about
# a model of it, and this is the step that makes that true: Charon reads the
# Rust the compiler reads and writes LLBC, Aeneas turns the LLBC into Lean.
# The generated file is committed, so a reader can see what was proved without
# running any of this, and CI regenerates it and fails if it has drifted.
#
# Both tools are pinned. Aeneas and Charon move together and a mismatch shows
# up as a translation that silently omits a function rather than as an error.
set -euo pipefail

cd "$(dirname "$0")/.."

CHARON="${CHARON:-charon}"
AENEAS="${AENEAS:-aeneas}"
OUT="lean-verified/NoxVerified.lean"
LLBC="${TMPDIR:-/tmp}/nox_verified.llbc"

for tool in "$CHARON" "$AENEAS"; do
    if ! command -v "$tool" >/dev/null 2>&1 && [ ! -x "$tool" ]; then
        echo "$tool not found. Set CHARON and AENEAS to the pinned binaries." >&2
        echo "See lean/README.md for which versions this tree expects." >&2
        exit 1
    fi
done

echo "charon: $("$CHARON" version 2>/dev/null || echo unknown)"
echo "aeneas: $("$AENEAS" -version 2>/dev/null || echo unknown)"

# The aeneas preset is what makes the LLBC readable by Aeneas at all: it turns
# off the optimisations that erase the structure the translation needs.
( cd verified && "$CHARON" cargo --preset=aeneas --dest-file "$LLBC" )

"$AENEAS" -backend lean "$LLBC" -dest lean-verified -namespace NoxVerified

if [ ! -s "$OUT" ]; then
    echo "the translation wrote nothing to $OUT" >&2
    exit 1
fi

# A translation that produced no definitions is a translation that failed
# quietly, which is how a proof ends up being about an empty namespace.
definitions=$(grep -c '^def ' "$OUT" || true)
if [ "$definitions" -eq 0 ]; then
    echo "$OUT carries no definitions" >&2
    exit 1
fi

echo "extracted $definitions definitions into $OUT"
