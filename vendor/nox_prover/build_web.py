#!/usr/bin/env python3
# NONOS Operating System (AGPL-3.0-or-later)
"""Build the browser prover: wasm with shared memory, so a page proves on
every core.

    python3 nox_prover/build_web.py --out <dir> [--single]

<dir> receives the whole browser package: nox.js (the API), nox-worker.js,
and pkg/ (the wasm and its bindings). A page imports `Prover` from nox.js.

The threaded build needs a nightly toolchain with rust-src and the
wasm32-unknown-unknown target, and wasm-bindgen-cli at the version in
Cargo.lock. The page that loads it must be served with

    Cross-Origin-Opener-Policy: same-origin
    Cross-Origin-Embedder-Policy: require-corp

or the browser gives it no SharedArrayBuffer and initThreadPool fails.
--single builds the one-thread form on stable, for pages that cannot send
those headers.
"""

import argparse
import glob
import os
import re
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Shared memory, imported so the workers can be handed the same instance, and
# the TLS symbols wasm-bindgen-rayon initialises each worker with. 4 GiB is
# the wasm32 ceiling; a proof needs about 2.3 GB of it.
THREAD_FLAGS = [
    "-C", "target-feature=+atomics,+bulk-memory,+mutable-globals",
    "-C", "link-arg=--shared-memory",
    "-C", "link-arg=--import-memory",
    "-C", "link-arg=--max-memory=4294967296",
    "-C", "link-arg=--export=__wasm_init_tls",
    "-C", "link-arg=--export=__tls_size",
    "-C", "link-arg=--export=__tls_align",
    "-C", "link-arg=--export=__tls_base",
]


def run(cmd, env=None):
    print("+", " ".join(cmd), flush=True)
    subprocess.run(cmd, cwd=ROOT, env=env, check=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", required=True, help="directory for the JS and wasm")
    ap.add_argument("--single", action="store_true", help="one thread, stable toolchain, no header requirement")
    a = ap.parse_args()

    env = dict(os.environ)
    target_dir = os.path.join(ROOT, "target-web-single" if a.single else "target-web")
    env["CARGO_TARGET_DIR"] = target_dir
    if a.single:
        cmd = ["cargo", "build", "--release", "--target", "wasm32-unknown-unknown",
               "-p", "nox_prover", "--lib", "--features", "wasm"]
    else:
        env["RUSTFLAGS"] = " ".join(THREAD_FLAGS)
        cmd = ["cargo", "+nightly", "build", "--release", "--target", "wasm32-unknown-unknown",
               "-p", "nox_prover", "--lib", "--features", "wasm-threads",
               "-Z", "build-std=panic_abort,std"]
    run(cmd, env)

    wasm = os.path.join(target_dir, "wasm32-unknown-unknown", "release", "nox_prover.wasm")
    pkg = os.path.join(a.out, "pkg")
    run(["wasm-bindgen", "--target", "web", "--out-dir", pkg, wasm])
    for f in ("nox.js", "nox-worker.js"):
        shutil.copy(os.path.join(ROOT, "nox_prover", "web", f), os.path.join(a.out, f))

    if not a.single:
        # wasm-bindgen-rayon's worker imports the package as '../../..', which
        # a bundler resolves through package.json and a plain page cannot: it
        # names a directory. Point it at the module itself.
        helpers = glob.glob(os.path.join(pkg, "snippets", "*", "src", "workerHelpers.js"))
        if len(helpers) != 1:
            sys.exit(f"expected one workerHelpers.js under {pkg}/snippets, found {len(helpers)}")
        text = open(helpers[0]).read()
        fixed, n = re.subn(r"import\('\.\./\.\./\.\.'\)", "import('../../../nox_prover.js')", text)
        if n != 1 and "nox_prover.js" not in text:
            sys.exit(f"{helpers[0]}: the package import was not where it is expected; check the wasm-bindgen-rayon version")
        open(helpers[0], "w").write(fixed)
    print(f"built {a.out}", flush=True)


if __name__ == "__main__":
    main()
