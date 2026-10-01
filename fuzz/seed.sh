#!/usr/bin/env bash
# Seed each corpus with an input of the shape its parser accepts.
#
# A fuzzer with no corpus tests the length check and nothing behind it. A sealed
# note is 1,186 bytes starting with its version, a store frame carries a four
# byte length and an eight byte counter, and a row begins with its kind.
set -euo pipefail

cd "$(dirname "$0")"

seed() {
    mkdir -p "corpus/$1"
    shift
    python3 -c "
import pathlib, sys
target, size, first = sys.argv[1], int(sys.argv[2]), sys.argv[3]
body = bytes([int(first)]) + bytes((i * 7 + 11) % 256 for i in range(size - 1))
pathlib.Path(target).write_bytes(body)
" "$@"
}

# The note harness reads a 1,186 byte sealed note and then the 32 byte leaf it
# is checked against, because a pool chooses both.
seed note                corpus/note/sealed-1186           1186 1
seed note                corpus/note/sealed-1218           1218 1
seed store_frame         corpus/store_frame/frame-140      140 0
seed store_row           corpus/store_row/found-130        130 1
seed store_row           corpus/store_row/status-33        33  2
seed store_row           corpus/store_row/cursor-9         9   3
seed address             corpus/address/text-63            63  110
mkdir -p corpus/rpc
printf '%s' '{"jsonrpc":"2.0","id":1,"result":"0x10"}' > corpus/rpc/block-number
printf '%s' '{"jsonrpc":"2.0","id":1,"result":[]}' > corpus/rpc/no-logs

# The account reader takes a batch placed by id, the lander a two byte status then its JSON, the
# policy and the registry ABI words, the typed parsers text, and the disk readers a file.
mkdir -p corpus/account corpus/lander corpus/policy corpus/typed corpus/disk
python3 -c "
import json, pathlib
answers = [{'jsonrpc': '2.0', 'id': i, 'result': '0x' + format(i + 1, '064x')} for i in range(16)]
pathlib.Path('corpus/account/batch-16').write_text(json.dumps(answers))
pathlib.Path('corpus/account/block').write_text('{\"id\":1,\"result\":{\"baseFeePerGas\":\"0x3b9aca00\",\"timestamp\":\"0x66\"}}')
pathlib.Path('corpus/lander/queued').write_bytes(bytes([0, 202]) + b'{\"id\":\"h-1\"}')
pathlib.Path('corpus/lander/state').write_bytes(bytes([0, 200]) + b'{\"status\":\"settled\",\"tx\":\"0x' + b'ab' * 32 + b'\"}')
words = b''.join(v.to_bytes(32, 'big') for v in [5, 1, 2, 3, 4, 1])
pathlib.Path('corpus/policy/schedule').write_bytes(words)
pathlib.Path('corpus/typed/address').write_text('0x9858EfFD232B4033E47d90003D41EC34EcaEda94')
pathlib.Path('corpus/typed/amount').write_text('0.37')
pathlib.Path('corpus/disk/published').write_text('1790841600 1790842500 2 lander h-1\n')
pathlib.Path('corpus/disk/publics').write_text('{\"publics\": [' + ', '.join(str(i) for i in range(37)) + ']}\n')
"


find corpus -type f | sort | sed 's/^/  /'
