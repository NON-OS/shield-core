#!/usr/bin/env bash
# Build the browser core and prover into <out>/pkg.
#
# Usage: web/scripts/build-wasm.sh threads|single <out>
#
# threads is shared-memory wasm: every core, through a rayon pool on Web Workers. It needs the
# nightly named in web/toolchain with rust-src, because std has to be rebuilt with atomics, and a
# page served cross-origin isolated. single is the one-thread form on the pinned stable toolchain,
# for a browser that will not isolate the page. Paths are remapped as phone-libs.sh does, so two
# builds of one commit on two machines give the same bytes.
set -euo pipefail

form="${1:?threads or single}"
out="${2:?an output directory}"
# Extra crate features, for a debug build: WEB_FEATURES=panic-report.
extra="${WEB_FEATURES:-}"
core="$(cd "$(dirname "$0")/../.." && pwd)"
cargo_home="${CARGO_HOME:-$HOME/.cargo}"
remap="--remap-path-prefix=$HOME=/home --remap-path-prefix=$cargo_home=/cargo --remap-path-prefix=$core=/nox-shield-core"
target="$core/target/web-$form"
bindgen_version="$(grep -A1 '^name = "wasm-bindgen"$' "$core/Cargo.lock" | sed -n 's/^version = "\(.*\)"$/\1/p')"

if [ "$(wasm-bindgen --version | cut -d' ' -f2)" != "$bindgen_version" ]; then
    echo "wasm-bindgen-cli must be $bindgen_version, the version in Cargo.lock" >&2
    exit 1
fi

case "$form" in
threads)
    # Shared memory the workers are handed, and the thread-local symbols wasm-bindgen-rayon starts
    # each worker with. The ceiling is wasm32's 4 GiB.
    export RUSTFLAGS="$remap -C target-feature=+atomics,+bulk-memory,+mutable-globals \
        -C link-arg=--shared-memory -C link-arg=--import-memory \
        -C link-arg=--max-memory=4294967296 \
        -C link-arg=--export=__wasm_init_tls -C link-arg=--export=__tls_size \
        -C link-arg=--export=__tls_align -C link-arg=--export=__tls_base"
    CARGO_TARGET_DIR="$target" cargo "+$(cat "$core/web/toolchain")" build --profile web \
        --target wasm32-unknown-unknown -p nox_shield_web --features "threads,$extra" \
        -Z build-std=panic_abort,std
    ;;
single)
    export RUSTFLAGS="$remap"
    CARGO_TARGET_DIR="$target" cargo build --profile web --target wasm32-unknown-unknown -p nox_shield_web \
        --features "$extra"
    ;;
*)
    echo "threads or single, not $form" >&2
    exit 1
    ;;
esac

rm -rf "$out/pkg"
wasm-bindgen --target web --no-typescript --out-dir "$out/pkg" \
    "$target/wasm32-unknown-unknown/web/nox_shield_web.wasm"

if [ "$form" = threads ]; then
    # wasm-bindgen-rayon's worker imports its package as '../../..', which a bundler resolves
    # through package.json and a static page cannot. Point it at the module itself.
    helpers=("$out"/pkg/snippets/*/src/workerHelpers.js)
    if [ "${#helpers[@]}" -ne 1 ] || ! grep -q "import('../../..')" "${helpers[0]}"; then
        echo "workerHelpers.js is not where it is expected; check the wasm-bindgen-rayon version" >&2
        exit 1
    fi
    sed -i "s|import('../../..')|import('../../../nox_shield_web.js')|" "${helpers[0]}"
fi
echo "built $form into $out/pkg"
