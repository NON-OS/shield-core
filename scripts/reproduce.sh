#!/usr/bin/env bash
# Two builds of this commit, each from clean in its own directory, compared byte for byte. A
# difference fails, and the bytes that differ are printed.
#
# Usage: scripts/reproduce.sh android|ios
set -euo pipefail

platform="${1:?android or ios}"
core="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

if [ -n "$(git -C "$core" status --porcelain --untracked-files=no)" ]; then
    echo "the checkout has changes, so its commit is not what would be built" >&2
    exit 1
fi
commit="$(git -C "$core" rev-parse HEAD)"
for n in one two; do
    git -C "$core" worktree add --detach "$work/$n-tree" "$commit" >/dev/null
    "$work/$n-tree/scripts/phone-libs.sh" "$platform" "$work/$n" > "$work/$n.sums"
    git -C "$core" worktree remove --force "$work/$n-tree"
done

echo "commit $commit"
cat "$work/one.sums"
if ! diff "$work/one.sums" "$work/two.sums"; then
    echo "two builds of one commit differ" >&2
    (cd "$work" && find one -type f | while read -r f; do cmp -l "$f" "two/${f#one/}" | head -5; done) >&2
    exit 1
fi
echo "identical"
