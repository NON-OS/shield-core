# Accounts, view keys and key export

How one phrase holds several accounts, what a view key shows and what it cannot do, and what the
wallet exports. What is checked and what is not is in [20-security-status.md](20-security-status.md).

> [!WARNING]
> A view key shows every note of its account, past and future, to whoever holds it. It cannot be
> revoked. The only way to stop it is to move the value to a new account.

## Accounts

Account 0 is derived as every wallet derives it: each key from the 64-byte seed under its BLAKE3
context. Account i, for i of 1 or more, derives from the seed, the bytes `account` and i as four
little endian bytes (`keys::material`). No key of one account can be computed from another.

| Key | Derived from | Power |
|---|---|---|
| spend secret `sk` | `nox-shield 2026 spend key v1` | spends notes, never exported |
| `spend_pk`, `nk` | Poseidon of `sk`, in the circuit | receive, find spent notes |
| X-Wing receiving seed | `nox-shield 2026 receive key v1` | opens notes sent to the account |
| note store key | `nox-shield 2026 note store key v1` | seals the account note log |
| public account | BIP-32 at `m/44'/60'/0'/0/i` | the standard account at index i |

Each account keeps its own sealed note log: `notes.log` for account 0 and `notes-i.log` after it.
The number of accounts and the active one are in `account/accounts`, two numbers and no key, and a
wallet with one account writes no such file.

One fetched history is scanned for every account (`ffi/wallet/sync_each.rs`), so the reads are the
same whatever the number of accounts. Calls about one account, to the lander or its public account,
use circuits no other account uses (`net/tor/account.rs`). The pool scan stays shared.

A restore takes a phrase of 12, 15, 18, 21 or 24 words, so a phrase from any standard wallet comes in. A new
phrase is always 24 words. After a restore the wallet looks at accounts 1, 2 and on, each for a note
or any public use on mainnet or Sepolia, and stops after five empty ones in a row
(`ffi/wallet/find.rs`). It looks at five accounts at once, each over its own circuits, while the
pool history is fetched, and reports how many it has looked at. On the server, with Tor already
up, a phrase never used took 12.6 seconds.

## A fresh address for each withdrawal

A withdrawal is public, so it pays an address that has never been used. The send screen fills in
the public address of the account after the last one in use (`ffi/wallet/withdraw_to.rs`), which
the recovery words restore like any other account. An address typed in its place is checked over
Tor for a past transaction or a balance on Sepolia, and the screen warns when it finds one. A wallet
from a private key has one account, so it has no fresh address to offer, and the owner types
one.

## A wallet from a private key

A private key can be restored in place of words (`restore_from_key`). Its public account is that
key. Its shield keys derive from 64 bytes drawn from the key with BLAKE3 under the label
`nox-shield 2026 imported key seed v1`, so no shield key leads back to the key, and the same key
restored twice gives the same shield. The vault seals the 32-byte key under its own magic and
associated data (`custody/format.rs`, version 3). Such a wallet has one account, since a bare key
has no path to more, and no words to show. Exporting its public key returns the key itself.

## View keys

| Key | Holds | Shows | Cannot |
|---|---|---|---|
| `noxivk1` | the X-Wing seed and `spend_pk` | every note received, checked against its leaf | tell which notes are spent, spend |
| `noxfvk1` | the same and `nk` | also which notes are spent, so the balance and its history | spend |

The text is the prefix, then base32 of these bytes:

| Bytes | Incoming | Full |
|---|---|---|
| version `0x01` | 1 | 1 |
| X-Wing seed | 32 | 32 |
| `spend_pk`, four little endian words | 32 | 32 |
| `nk`, four little endian words | none | 32 |
| BLAKE3 checksum | 4 | 4 |
| zero pad | 1, to 70 | 4, to 105 |

The address alphabet encodes whole five-byte groups, so 69 bytes are padded to 70 and 101 to 105.
The pad comes after the checksum and must be zero, so one key has one text form. The checksum
hashes the tag `nox-shield/viewkey/v1`, the prefix and the key bytes, so an incoming key relabelled
as a full one fails on it. A reader refuses a wrong prefix, version, checksum or pad, and a word at
or above p (`keys/view_key_read.rs`).

Exporting a view key needs the `view-key-export` feature of the core, off by default. A release
has no view-key export until the two open items in
[20-security-status.md](20-security-status.md) are answered. Importing a view key is open.

A view key the wallet is given becomes a view-only account: kept in `watching.seal` under a key
derived from the seed, with its own sealed log, scanned with the rest, and with no send.

## Key export

| What | How |
|---|---|
| Recovery words | after the keystore confirms the owner, on a screen that blocks screenshots, never copied. A vault written before version 2 holds no words, and the screen says to move the value to a new wallet whose words are written down |
| View keys | per account, after the keystore confirms the owner, in a build with `view-key-export` only |
| Public account private key | per account, after the keystore confirms the owner. It shows nothing of the shield |
| Spend secret alone | never |

Each export opens the vault again, so the device asks for the owner every time
(`ffi/wallet/export.rs`). A vault written before version 2 holds the seed only, and so has no words
to show (`custody/format.rs`).

## Vectors

Each refusal below is built from account 0 with one thing wrong, and the checksum made right again
where the fault is not the checksum (`keys/view_key_refusals_test.rs`). Every one must be refused.

wrong checksum:

```text
noxivk1aedb3jxfu4aojpai7gh2uoy4qt5lrko2skq4cl5xopdlzhzws6xkit4vmdzg4ffns3phya3dknt6bxklxypbmf6ia32vbgtkbmqbrtlux2ddf5ya
```

wrong version:

```text
noxivk1aidb3jxfu4aojpai7gh2uoy4qt5lrko2skq4cl5xopdlzhzws6xkit4vmdzg4ffns3phya3dknt6bxklxypbmf6ia32vbgtkbmqbrtluvinswnya
```

relabelled prefix:

```text
noxfvk1aedb3jxfu4aojpai7gh2uoy4qt5lrko2skq4cl5xopdlzhzws6xkit4vmdzg4ffns3phya3dknt6bxklxypbmf6ia32vbgtkbmqbrtlux6ddf5ya
```

unknown prefix:

```text
noxxvk1aedb3jxfu4aojpai7gh2uoy4qt5lrko2skq4cl5xopdlzhzws6xkit4vmdzg4ffns3phya3dknt6bxklxypbmf6ia32vbgtkbmqbrtlux6ddf5ya
```

non-zero pad:

```text
noxfvk1aedb3jxfu4aojpai7gh2uoy4qt5lrko2skq4cl5xopdlzhzws6xkit4vmdzg4ffns3phya3dknt6bxklxypbmf6ia32vbgtkbmqbrtlujcshnfqde7moxavqzyluitm24v2mqfguzqoqr5bwsskf3dwaepm2bgqieuaaaaab
```

spend_pk word at p:

```text
noxivk1aedb3jxfu4aojpai7gh2uoy4qt5lrko2skq4cl5xopdlzhzws6xkiaiaaaap777777phya3dknt6bxklxypbmf6ia32vbgtkbmqbrtlur6duduaa
```

nk word at p:

```text
noxfvk1aedb3jxfu4aojpai7gh2uoy4qt5lrko2skq4cl5xopdlzhzws6xkit4vmdzg4ffns3phya3dknt6bxklxypbmf6ia32vbgtkbmqbrtluaeaaaah777777avqzyluitm24v2mqfguzqoqr5bwsskf3dwaepmspowy2iaaaaaa
```

The keys and addresses of accounts 0, 1 and 2 follow.

For the phrase "abandon" eleven times then "about", pinned in `keys/accounts_vectors.rs` and
`keys/view_key_test.rs`:

| Account | Public account |
|---|---|
| 0 | `0x9858EfFD232B4033E47d90003D41EC34EcaEda94` |
| 1 | `0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0` |
| 2 | `0xb6716976A3ebe8D39aCEB04372f22Ff8e6802D7A` |

Account 0, incoming:

```text
noxivk1aedb3jxfu4aojpai7gh2uoy4qt5lrko2skq4cl5xopdlzhzws6xkit4vmdzg4ffns3phya3dknt6bxklxypbmf6ia32vbgtkbmqbrtlux6ddf5ya
```

Account 0, full:

```text
noxfvk1aedb3jxfu4aojpai7gh2uoy4qt5lrko2skq4cl5xopdlzhzws6xkit4vmdzg4ffns3phya3dknt6bxklxypbmf6ia32vbgtkbmqbrtlujcshnfqde7moxavqzyluitm24v2mqfguzqoqr5bwsskf3dwaepm2bgqieuaaaaaa
```

Account 1, incoming:

```text
noxivk1ae2su2ufl6phtmctr5wr5t2n6dr4qmkuaifbuq5wy7d6wmh4we65nz7a2uy4fm3dvaj45tj2r7lueyy5bma2guto6oxrw55siwm3g54gwwyk3rqa
```

Account 1, full:

```text
noxfvk1ae2su2ufl6phtmctr5wr5t2n6dr4qmkuaifbuq5wy7d6wmh4we65nz7a2uy4fm3dvaj45tj2r7lueyy5bma2guto6oxrw55siwm3g54gwja2rmrfqugz2x6uyhhs4yesonxusqz2mlhp4ydk3cc2zgopzzlt5qk6s4aaaaaa
```

Account 2, incoming:

```text
noxivk1afi3hp4lflfn7ukur73dddqtfnvuveeie5a4otcravpxvvfeauu26bhqaq2numctv5zbnkctljje3wrfm3z3jd66yghlspoxcx2ctj57nvmecgaa
```

Account 2, full:

```text
noxfvk1afi3hp4lflfn7ukur73dddqtfnvuveeie5a4otcravpxvvfeauu26bhqaq2numctv5zbnkctljje3wrfm3z3jd66yghlspoxcx2ctj57g7f6go64scwfir6okvjjxroodfh7p4oih6mbwkelj7744ojwpzsbwwi2oaaaaaaa
```
