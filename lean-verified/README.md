# Proofs about the Rust that ships

`NoxVerified.lean` is generated. Charon reads `../verified/src` as the compiler reads it and writes
LLBC, and Aeneas turns the LLBC into this file. It is committed, so a reader can see what was proved
without running either tool, and the `verify` workflow regenerates it on every push and fails if the
committed copy differs.

`LimbProofs.lean`, `AmountProofs.lean`, `TransferProofs.lean`, `Base32Proofs.lean` and
`FeeProofs.lean` are written by hand, about the generated definitions. There are 20 theorems. Every
one rests on the three axioms of Lean, `propext`, `Classical.choice` and `Quot.sound`, and nothing
else: the workflow prints the axioms of each theorem and fails on a fourth. That rules out a `sorry`, which shows as `sorryAx`,
and a call to a SAT solver, which shows as a `_native` axiom.

| Theorem | What it proves |
|---|---|
| `the_halves_rebuild_the_value` | splitting a `u64` into two 32-bit limbs and rebuilding it returns the value, for all 2^64 values, without a panic |
| `split_fraction_is_below_the_scale` | the base units left after the whole tokens are always below 10^18 |
| `split_then_combine_is_the_identity` | showing a balance as a decimal and reading it back loses nothing, and neither direction can fail |
| `combine_refuses_a_carrying_fraction` | a fraction of 10^18 or more is refused and never folded into the whole |
| `the_transfer_balances` | whenever a transfer is planned, the two notes spent equal the amount, the fee and the change, with no wrap |
| `a_covering_pair_is_never_refused` | two notes that cover the amount and the fee always yield a change |
| `an_uncovered_pair_is_refused` | two notes that fall short are refused, never paid short |
| `a_glyph_reads_back_as_its_symbol` | each of the 32 address symbols has one character, and it reads back as that symbol |
| `a_symbol_writes_the_glyph_that_read_it` | a character that reads as a symbol is the character that symbol writes, so the alphabet is a bijection |
| `five_bytes_survive_the_round_trip` | five bytes to eight symbols and back is the identity, for all 2^40 groups |
| `five_bytes_have_one_spelling` | any eight symbols the decoder accepts are the eight the encoder writes |
| `three_bytes_survive_the_round_trip` | the same for the three-byte tail of an address and its five symbols |
| `a_set_padding_bit_is_refused` | the padding bit of the tail is written as zero and refused when set, so an address has one spelling |
| `three_bytes_have_one_spelling` | any five tail symbols the decoder accepts are the five the encoder writes |
| `the_token_fee_adds_back` | whenever a token fee is split off a send, what arrives and the fee add back to the amount, the fee is the amount times the rate rounded down, and it is below the amount |
| `a_fee_of_the_whole_is_refused` | a rate that would take the whole amount is refused, never sent as a transfer of nothing |
| `the_offer_is_held_to_the_ceiling` | an offer has a tip of at most 5 gwei and at most what was suggested, and a cap of twice the base fee plus the tip, at most 1,000 gwei |
| `an_offer_past_the_ceiling_is_refused` | a base fee whose double passes 1,000 gwei gets no offer at all |
| `the_nonce_is_the_larger` | the nonce signed is the larger of the pending count and the recorded nonce, so no send reuses a nonce |
| `covers_is_the_true_sum` | the balance check answers yes when the amount and the fee add up to at most the balance, as numbers, and no otherwise, with no wrapped sum |

Everything here is bounded as the machine is: `U64` is a 64-bit bitvector, a shift is the checked
one Rust performs, and nothing is widened to a natural number to make the arithmetic easier. Each
statement is a Hoare triple, which holds only when the code returns, so it also says the code cannot
panic on those inputs.

## The fee arithmetic

`verified/src/fee.rs` holds the arithmetic of a public send: `split_fee` (what arrives and the token
fee), `offer` (the tip and the fee cap), `next_nonce` and `covers`. The core calls these, and
`FeeProofs.lean` proves the six theorems above about them. The same functions are also checked for
every input by Kani in the core, as [20-security-status.md](../docs/20-security-status.md) lists.

## The tools

| Tool | Revision | Where it is pinned |
|---|---|---|
| Aeneas | `45061fa` | `flake.nix`, `flake.lock` |
| Charon | `40ee060a8`, as the Aeneas flake exports it | `flake.lock` |
| Lean | 4.31.0 | `lean-toolchain` |

Aeneas and Charon move together. A mismatch between them omits a function from the translation
without failing, so both come from one lock.

## Building it

```sh
nix build .#extraction                       # from the repository root: the translation
cp result/NoxVerified.lean lean-verified/    # only when the Rust in verified/src changed
cd lean-verified && lake build               # the proofs; fetches mathlib through Aeneas
```

`nix build .#checks.x86_64-linux.extraction` fails if the committed translation differs from what
the Rust produces.
