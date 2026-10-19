#!/usr/bin/env bash
# Text this repository will not carry, in every tracked file of its own: en and em dashes, markers
# of unfinished work, invisible and bidirectional control characters, and strings shaped like a
# credential. Copied trees are left out, since they are checked where they come from.
set -euo pipefail

cd "$(dirname "$0")/.."
# Code points above 0x7f are matched only under a UTF-8 locale.
export LC_ALL=C.UTF-8

mapfile -d '' tracked < <(git ls-files -z | grep -zv -e '^vendor/' -e '^ci/verify-kit/lib/' \
    -e '^fuzz/corpus/' -e 'Cargo\.lock$' -e 'package-lock\.json$' -e '^scripts/check-text\.sh$')
# Text files only: -I passes over anything binary, such as the figures and the fonts.
mapfile -d '' text < <(grep -IlZ '' -- "${tracked[@]}" || true)

failed=0
check() {
    local what="$1" pattern="$2"
    local hits status=0
    hits="$(grep -nP -e "$pattern" -- "${text[@]}")" || status=$?
    # grep exits 1 for no match and 2 for an error, which fails the check.
    if [ "$status" -gt 1 ]; then
        echo "$what: the search failed" >&2
        failed=1
    elif [ -n "$hits" ]; then
        echo "$what:" >&2
        echo "$hits" | head -20 >&2
        failed=1
    fi
}

check "en or em dash" '[\x{2013}\x{2014}]'
check "unfinished marker" '\b(TODO|FIXME|XXX)\b'
check "invisible or bidirectional character" '[\x{200B}-\x{200F}\x{202A}-\x{202E}\x{2066}-\x{2069}\x{FEFF}]'
check "private key block" '-----BEGIN [A-Z ]*PRIVATE KEY-----'
check "RPC URL with a key in it" '(infura\.io/v3|alchemy\.com/v2|quiknode\.pro|ankr\.com/[a-z_]+)/[A-Za-z0-9_-]{16,}'
check "cloud access key" '\b(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|xox[baprs]-[A-Za-z0-9-]{10,})\b'

if git ls-files | grep -qE '(^|/)\.env(\.|$)'; then
    echo "an .env file is tracked" >&2
    failed=1
fi

if [ "$failed" -ne 0 ]; then
    exit 1
fi
echo "text checks pass"
