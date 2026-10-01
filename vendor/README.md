# Vendored source

The core builds against these crates, copied here as source so that any machine, a CI runner
included, builds the same code the tests ran against, and nothing is fetched from anywhere but
crates.io.

| Crate | Source | Commit | Notes |
|---|---|---|---|
| `nonos-stark`, `stark_proofs`, `nox_prover` | tarball `prover-src-e8f02a0.tar.gz`, SHA-256 `dc147f9624c3a1fe26513505cecb09a6bc540da68f37feb16ee55a473b1f0748`, from `git archive --format=tar --prefix=prover-src-e8f02a0/ e8f02a0 nonos-stark stark_proofs nox_prover \| gzip -n` in the STARK repository, built with `--features not_before` | `e8f02a0` | the production pool: the 37-limb statement with the not-before time on a 600-second grid. Periodic root `898b800f60f467f04ac9140fb425cd54181e4d1642f61fc38b5965d08ace2888`, unchanged, shape A parameter id `ccba76ed5748b5ee54dfd62935fd1d10998b5c0f84e35a9dc899905cfb1eadb5`, image hash `4364151e9f54797f3bbf9c8d28465f5a7dcf8ca1aafa9c9b48eb43cedf4e2429`. The four pinned 37-limb wallet vectors prove byte for byte, in their format 5 and format 7 forms (`core/tests/prod_vectors.rs`), and their single-call layout is accepted by the production verifier `0xDA9dD4A3e957AFD2179131273C93dabBA1186A44`. The pin `1b4b5a3` changes only attestation code, tests and Lean text, with `nox_prover`, `nonos-stark` and the vectors unchanged, and its `stark_proofs` reads `../lean` from outside the crate, so it is not taken until that is gated |
| v2 prover, replaced by the row above | tarball `prover-src-v2.tar.gz`, SHA-256 `c6ba553bd29bb2c72b02e240598f829be5ab9190660a2676bcee48938120d0fa`, built with `--features v2` | v2 | v2: format 7 proofs in the shared form, radix 8, 32-byte digests, the checkpoint rule, the rank check inside the prover. Periodic root `898b800f60f467f04ac9140fb425cd54181e4d1642f61fc38b5965d08ace2888`, shape A parameter id `add18dbb2dba8c5426d79bca1187f6c5221a5e86108cc49ce0909d958bb5a80a`. The four pinned v2 proofs verified with it |
| launch prover, replaced by the row above | tarball `nox-shield-src-2e2ade7.tar.gz`, SHA-256 `2c42253ea451333e6e39f92aaf1d7d1c232f2daa37f48f158818e3f4ef6313a5` | `2e2ade7` | the launch prover: route 2, standard sizes per asset, change to the key of the spender exempt from them, and the zero-knowledge rank check opening each mask column on its own, 304 row functionals over distinct rows. Its proofs are 112,956 bytes and are accepted by the live launch verifier. The circuit root, as `docs/13-launch.md` in the tarball records it, is `bb7614937ae6d7e5e26e88610fae8ff9e5195fef4721fdbd` |
| `nonos_hd`, `nonos_seal` | the `userland/` tree of the NØNOS source | `51ceb73b7` | BIP-39 words and seed, BIP-32 derivation, and the seal the vault uses at rest. `nonos_hd` carries one uncommitted change to a doc comment and no change to code |

Against that tarball, the three prover crates here differ in no file. On 1 October they were also
compared with a checkout of the STARK repository at `e8f02a0`: `diff -rq` finds no file that differs
in `nox_prover`, `nonos-stark` or `stark_proofs`, and `git diff e8f02a0 1b4b5a3` touches none of
`nox_prover`, `nonos-stark` and `spec/wallet-vectors-not-before`.

`nox_prover` compiles its C functions, `nox_prove`, `nox_prove_ex`, `nox_verify` and `nox_free`,
into every build, so they reach the phone libraries although no app calls them. `llvm-nm -D` of both
Android libraries built on 1 October lists 335 exported symbols: 331 are the uniffi binding, and the
other four are these. A feature that leaves them out is asked of the STARK lane, since nothing here
is edited by hand.

## `spec/`

`spec/wallet-vectors/transfer-eth/` holds two files from the same tarball: `proof.bin`, a launch
proof of 112,956 bytes, and `publics.json`, its 36 public words. `zk_rank_test` in `stark_proofs`
reads both. Both are public: a proof and its public words are what a settlement puts on chain. The
witness files published beside them, `seed.json`, `entropy.hex` and `request.json`, are not copied,
because they open the notes the proof spends.

## Moving a crate forward

Replace its directory with the new source from a published tarball whose SHA-256 has been checked,
record the commit and the hash here, and run the full gate, including a launch proof accepted by the
live verifier. Nothing is edited here by hand: a change made only in this copy is one the next
update discards. Format the core crates by name, `cargo fmt -p nox_shield_core -p nox_verified`,
because formatting the whole workspace rewrites these files.
