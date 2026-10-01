#!/usr/bin/env python3
# NONOS Operating System (AGPL-3.0-or-later)
"""Build the prover as the static library a phone wallet links.

    python3 nox_prover/build_ios.py --out <dir> [--android]

Writes <dir>/<target>/libnox_prover.a for each target, and the C header
nox_prover.h, and prints each library's size. iOS builds the device
(aarch64-apple-ios) and the Apple-silicon simulator (aarch64-apple-ios-sim);
--android builds aarch64-linux-android. A static library needs no linker, so
this runs anywhere the Rust targets are installed; Xcode or the NDK links it
into the app.

The profile is `wallet` (workspace Cargo.toml): whole-program optimisation,
one codegen unit, panic=abort. The library opens no files and starts no
processes; the periodic cache comes in as bytes the app bundles.
"""

import argparse
import os
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IOS = ["aarch64-apple-ios", "aarch64-apple-ios-sim"]
ANDROID = ["aarch64-linux-android"]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", required=True)
    ap.add_argument("--android", action="store_true", help="build for Android instead of iOS")
    a = ap.parse_args()

    targets = ANDROID if a.android else IOS
    env = dict(os.environ, CARGO_TARGET_DIR=os.path.join(ROOT, "target-mobile"))
    os.makedirs(a.out, exist_ok=True)
    for t in targets:
        cmd = ["cargo", "rustc", "--profile", "wallet", "-p", "nox_prover", "--features", "parallel",
               "--target", t, "--lib", "--crate-type", "staticlib"]
        print("+", " ".join(cmd), flush=True)
        if subprocess.run(cmd, cwd=ROOT, env=env).returncode != 0:
            sys.exit(f"the {t} build failed")
        lib = os.path.join(env["CARGO_TARGET_DIR"], t, "wallet", "libnox_prover.a")
        dst = os.path.join(a.out, t)
        os.makedirs(dst, exist_ok=True)
        shutil.copy(lib, dst)
        print(f"{t}: {os.path.getsize(lib) / 1e6:.1f} MB", flush=True)
    shutil.copy(os.path.join(ROOT, "nox_prover", "include", "nox_prover.h"), a.out)
    print(f"built {a.out}", flush=True)


if __name__ == "__main__":
    main()
