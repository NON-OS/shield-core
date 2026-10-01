#!/usr/bin/env bash
# Build the libraries the apps ship, with the flags their build scripts use, and print a hash of
# each. Every local path is remapped, so the bytes do not depend on where the checkout sits.
#
# Usage: scripts/phone-libs.sh android|ios <out dir>
set -euo pipefail

platform="${1:?android or ios}"
out="$(mkdir -p "${2:?out dir}" && cd "$2" && pwd)"
core="$(cd "$(dirname "$0")/.." && pwd)"
cargo_home="${CARGO_HOME:-$HOME/.cargo}"
export RUSTFLAGS="--remap-path-prefix=$HOME=/home --remap-path-prefix=$cargo_home=/cargo --remap-path-prefix=$core=/nox-shield-core"
export CFLAGS="-ffile-prefix-map=$HOME=/home -ffile-prefix-map=$cargo_home=/cargo -ffile-prefix-map=$core=/nox-shield-core"
export ZERO_AR_DATE=1 SOURCE_DATE_EPOCH=0
cd "$core"

case "$platform" in
android)
    : "${ANDROID_NDK_HOME:?set ANDROID_NDK_HOME to the NDK the Android app pins, r27}"
    for pair in aarch64-linux-android:arm64-v8a x86_64-linux-android:x86_64; do
        target="${pair%%:*}"
        abi="${pair##*:}"
        cargo ndk --target "$target" --platform 28 -- build --release -p nox_shield_core --lib
        mkdir -p "$out/$abi"
        cp "target/$target/release/libnox_shield_core.so" "$out/$abi/"
    done
    ;;
ios)
    for target in aarch64-apple-ios aarch64-apple-ios-sim; do
        cargo build --release --target "$target" -p nox_shield_core --lib
        mkdir -p "$out/$target"
        cp "target/$target/release/libnox_shield_core.a" "$out/$target/"
    done
    ;;
*)
    echo "android or ios" >&2
    exit 1
    ;;
esac

named="$(find "$out" -type f -exec strings -a {} + | grep -cF "$HOME/" || true)"
if [ "$named" != 0 ]; then
    echo "a library still names the home directory of this machine" >&2
    exit 1
fi
(cd "$out" && find . -type f | sort | xargs sha256sum)
