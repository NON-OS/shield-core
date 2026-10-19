#!/usr/bin/env bash
# Hand a browser proof to the production verifier's verifyBatch with eth_call: no transaction, no
# gas, no key. Prints the verifier's answer, true or false, or its revert.
#
# Usage: RPC=<sepolia rpc> VERIFIER=<address> web/bench/verifier-call.sh <folder>
#
# <folder> holds whole.hex and words.txt from the verifier_args test. The verifier's address is
# in L1-Shield docs/deployments.md.
set -euo pipefail

dir="${1:?a folder with whole.hex and words.txt}"
: "${RPC:?a Sepolia RPC}" "${VERIFIER:?the verifier address}"

data="$(python3 -I - "$dir" <<'PY'
import sys
d = sys.argv[1]
whole = bytes.fromhex(open(f"{d}/whole.hex").read().strip())
words = [int(w, 16) for w in open(f"{d}/words.txt").read().split()]
# The ABI of (bytes, uint256[]): two offsets, then the bytes padded to a word, then the array.
word = lambda n: n.to_bytes(32, "big")
pad = whole + b"\0" * (-len(whole) % 32)
head_bytes = 64
head_words = head_bytes + 32 + len(pad)
body = word(head_bytes) + word(head_words) + word(len(whole)) + pad + word(len(words)) + b"".join(map(word, words))
print(body.hex())
PY
)"
# The first four bytes of Keccak-256("verifyBatch(bytes,uint256[])").
selector=24fb8677
curl -sS -X POST -H 'content-type: application/json' "$RPC" --data @- <<JSON
{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"to":"$VERIFIER","data":"0x$selector$data","gas":"0x5f5e100"},"latest"]}
JSON
echo
