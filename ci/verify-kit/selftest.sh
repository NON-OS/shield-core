#!/usr/bin/env bash
# selftest.sh: the kit must accept the route-2 vector and refuse the pre-route-2 one. Run it before
# trusting a result, and in CI before the check of the build's own proof.
set -uo pipefail
cd "$(dirname "$0")"
shasum -a 256 -c SHA256SUMS --quiet 2>/dev/null || { echo "a kit file does not match SHA256SUMS"; exit 1; }
./verify.sh vectors/route2.proof vectors/route2.publics.json >/dev/null || { echo "FAIL: route-2 vector refused"; exit 1; }
if ./verify.sh vectors/pre-route2.proof vectors/pre-route2.publics.json >/dev/null; then echo "FAIL: pre-route-2 vector accepted"; exit 1; fi
echo "selftest passed: route 2 accepted, pre-route 2 refused"
