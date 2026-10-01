#!/usr/bin/env bash
# The dependency set is recomputed, not maintained by hand.
#
# Every crate in the resolved graph is a supply chain entry and a possible
# network endpoint, so the whole transitive set is written down in
# scripts/dependencies.allow and this recomputes it. A crate arriving through
# somebody else's dependency shows up as a diff in a commit rather than as
# nothing at all.
set -euo pipefail

cd "$(dirname "$0")/.."

if [ ! -d vendor/nonos-stark ]; then
    echo "run scripts/link-deps.sh first" >&2
    exit 1
fi

cargo metadata --format-version 1 > /tmp/nox-metadata.json

python3 - <<'PY' > /tmp/nox-dependencies.now
import json
with open("/tmp/nox-metadata.json") as handle:
    data = json.load(handle)
mine = {"nox_shield_core", "nox_field_kernel"}
for name in sorted({p["name"] for p in data["packages"] if p["name"] not in mine}):
    print(name)
PY

if ! diff -u scripts/dependencies.allow /tmp/nox-dependencies.now; then
    echo >&2
    echo "the dependency set changed. If that was deliberate, commit the new" >&2
    echo "scripts/dependencies.allow in the same commit, with the reason." >&2
    exit 1
fi

count=$(wc -l < scripts/dependencies.allow | tr -d ' ')
echo "$count dependencies, all accounted for"
