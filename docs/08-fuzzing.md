# Fuzzing

The parsers that read bytes someone else chose, the fuzz target for each, and what has been run.
Each is a place where a stranger decides what the code reads. What is checked and what is not is in
[20-security-status.md](20-security-status.md).

| Fuzz target | Parsers | Who chooses the bytes |
|---|---|---|
| `address` | `keys::parse_receiving_address` | whoever the user copied a `nox1` address from |
| `note` | `notes::open_xwing` | whoever wrote an `OutputNote` beside a leaf in the pool |
| `rpc` | the pool history decoders of `net::rpc`: a block number, logs, a batch of call results | an RPC server, which owes this wallet nothing |
| `account` | the reply reader of the public account, `evm::reply`, each answer read as a quantity, a word, data and raw JSON, the base fee and time of a block, a nonce record line, the swap market of each route, and the state of the NOX token | the same, for the public account |
| `lander` | the hand-off reply, the state reply and the info page of `net::relay::reply` | the lander onion service, which this wallet does not run |
| `policy` | the fee schedule and the percentages of the policy (`net::fee_schedule`), and the four replies of the rewards registry (`wallet::rewards::link_state`) | an RPC server answering for those contracts |
| `typed` | a view key, a private key, recovery words, an EVM address, an amount of each coin, and a signature pasted from another wallet | whoever the person copied them from |
| `disk` | the vault container (`custody::format::decode`), the public limbs of a hand-off, the single-call cut of a proof package, and the record of a publication | a seized or tampered device |
| `store_frame` | `store::frame::decode` | the same |
| `store_row` | `store::row::decode` | the same |

The property is the same for all ten: no input panics, loops without end, or allocates without
bound. A malformed input is an error value, never a partly applied record.

## Two layers

The sweep, `core/src/fuzz/sweep_test.rs`, runs in every `cargo test --workspace --all-features`,
on the pinned stable toolchain, in about a minute. `no_parser_panics_on_any_length` feeds each of
the ten entry points every length from zero up past its longest fixed record, and
`no_parser_panics_on_random_content` feeds several thousand buffers whose contents change and do
not grow, which is where a length field read from the input decides how much the parser trusts.

The fuzzers need a nightly toolchain and hours:

```sh
fuzz/seed.sh
cargo +nightly fuzz run account -- -max_total_time=86400
cargo +nightly fuzz list
```

The targets reach the parsers through `core::fuzz`, behind the `fuzzing` feature, which is off by
default, so a shipped library carries none of those symbols. A parser that is private to its module
is reached through a `fuzz_hook` file in that module, built only with the same feature. The fuzz
crate is its own workspace, so no fuzzing dependency can reach a phone.

## Seeds

A fuzzer with no corpus tests the length check and nothing behind it. `fuzz/seed.sh` writes inputs
of the shape each parser accepts: a sealed note of 1,186 bytes followed by the 32-byte leaf it is
checked against, a receiving address as text, an RPC reply, a batch of sixteen answers, a lander
reply with its status, a fee schedule as six ABI words, an address and an amount as text, a
publication record and the public limbs of a hand-off, a framed row, and a row of each kind.

The note harness reads both halves from the input, because a pool chooses both, and opens under a
receiving key derived from a fixed seed. That puts the X-Wing decapsulation, the view tag, the
ChaCha20-Poly1305 open with the leaf as associated data, and the plaintext checks within reach, past
the length check.

## What has been run

The release gate asks for 24 hours on each target with no crash, on the build server. That server
was not reachable from the session of 1 October, so the runs below were made on the machine that
session had: 4 virtual cores of an Intel Xeon at 2.10 GHz, all ten targets at once at the lowest
priority, each with `-max_total_time=86400`. Each line gives the time it ran, the executions, the
corpus it kept and what it found.

| Target | Ran for | Executions | Corpus | Found |
|---|---|---|---|---|
| `account` | about 3 h 45 min | 185,084,957 | 633 inputs, 79 KB | nothing |
| `address` | about 3 h 45 min | 684,323,141 | 135 inputs, 9.3 KB | nothing |
| `disk` | about 3 h 45 min | 747,270,076 | 286 inputs, 16 KB | nothing |
| `lander` | about 3 h 45 min | 616,477,120 | 252 inputs, 12 KB | nothing |
| `note` | about 3 h 45 min | at least 4,194,304 | 7 inputs, 7.0 KB | nothing |
| `policy` | about 3 h 45 min | at least 536,870,912 | 59 inputs, 11 KB | nothing |
| `rpc` | about 3 h 45 min | 323,499,639 | 473 inputs, 76 KB | nothing |
| `store_frame` | about 3 h 45 min | at least 1,073,741,824 | 1 input, 1 byte | nothing |
| `store_row` | about 3 h 45 min | at least 1,073,741,824 | 44 inputs, 2.2 KB | nothing |
| `typed` | about 3 h 45 min | 138,285,075 | 465 inputs, 47 KB | nothing |

The first run started at 09:46Z on 1 October and stopped at about 13:31Z, when the container of the session
was suspended for being idle. No target had crashed or written an artefact. A target
prints a line only when its corpus changes or its count reaches a power of two, so for the quiet
targets the count is the last power of two it printed. The disk of the container was full for a
few minutes at about 12:55Z and 12:58Z, while the test suite was linking, so an input found in
those minutes may not have been kept. The runs shared the 4 cores with test builds and the proving
profile, at the lowest priority.

A second run started at 13:56Z from the corpus the first one kept. A suspended container stops
its fuzzers, so a run here reaches 24 hours only if the session stays awake that long. The gate
still needs the build server.

## What a finding is

A crash becomes a test in the module that owns the parser, with the input that caused it, before
the fix lands. The corpus and the crash artefacts are not committed. A corpus is a working set, and
a crash that matters is a test, not a file nobody reads.
