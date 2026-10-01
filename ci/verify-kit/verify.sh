#!/usr/bin/env bash
# verify.sh PROOF PUBLICS: checks one launch proof against the live verifier. Needs RPC (a Sepolia
# endpoint) and Foundry. Exit 0 when the verifier accepts, 1 otherwise. Sends no transaction.
set -uo pipefail
cd "$(dirname "$0")"
: "${RPC:?set RPC to a Sepolia RPC URL}"
# Foundry reads only inside the kit, so the inputs are copied in first
w=$(mktemp -d ./input.XXXXXX); trap 'rm -rf "$w"' EXIT
cp "$1" "$w/spend.proof" && cp "$2" "$w/spend.proof.publics.json" || { echo "cannot read the inputs"; exit 1; }
out=$(PROOF="$w/spend.proof" PUBLICS="$w/spend.proof.publics.json" forge script script/VerifyLaunch.s.sol --rpc-url "$RPC" 2>&1)
if grep -q "the live verifier accepts this proof" <<<"$out"; then echo "accepted"; exit 0; fi
echo "refused: $(grep -oE 'Error[^\n]{0,160}' <<<"$out" | head -1)"; exit 1
