#!/usr/bin/env bash
# Point this workspace at the crates it builds against.
#
# The prover, the shield stack and the custody crates live in their own
# repositories. This makes the links the manifest expects, so no path on
# anybody's machine appears in a published file.
#
# Usage:
#   scripts/link-deps.sh <zkolang checkout> <os tree checkout>
set -euo pipefail

if [ "$#" -ne 2 ]; then
    echo "usage: $0 <zkolang checkout> <os tree checkout>" >&2
    exit 1
fi

ZK="$(cd "$1" && pwd)"
OS="$(cd "$2" && pwd)"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VENDOR="$ROOT/vendor"

mkdir -p "$VENDOR"

link() {
    local target="$1" name="$2"
    if [ ! -d "$target" ]; then
        echo "not found: $target" >&2
        exit 1
    fi
    rm -f "$VENDOR/$name"
    ln -s "$target" "$VENDOR/$name"
    echo "  $name -> $target"
}

echo "linking into $VENDOR"
link "$ZK/nonos-stark" nonos-stark
link "$ZK/stark_proofs" stark_proofs
link "$ZK/nonos_zkolang" nonos_zkolang
link "$OS/userland/nonos_hd" nonos_hd
link "$OS/userland/nonos_seal" nonos_seal

echo
echo "commits these links point at:"
printf '  zkolang %s\n' "$(git -C "$ZK" rev-parse --short HEAD 2>/dev/null || echo unknown)"
printf '  os tree %s\n' "$(git -C "$OS" rev-parse --short HEAD 2>/dev/null || echo unknown)"
