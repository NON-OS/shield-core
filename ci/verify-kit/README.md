# Launch proof verification kit

Checks a launch proof against the live verifier of the NØNOS Shield launch pool on Sepolia, with
no transaction and no gas. It was the release gate for the launch prover. The wallet now proves for
the v2 pool, whose proofs this kit does not read, and the kit is kept for the launch pool only.

    RPC=<sepolia rpc> ./selftest.sh                       # first: route 2 accepted, pre-route 2 refused
    RPC=<sepolia rpc> ./verify.sh spend.proof spend.proof.publics.json

- `spend.proof` is the package proof with its 40-byte NOXP header, 112,956 bytes.
- `spend.proof.publics.json` is `{"publics": [36 limbs]}`.
- The proof is re-encoded into the verifier's one-call layout exactly as the relayer encodes it for
  `settleBatch`, then handed to `verifyBatch` of the adapter the pool names.
- `verify.sh` exits 0 on acceptance and 1 on refusal, with the verifier's error.

Contents, all pinned in `SHA256SUMS`:

| Path | What |
|---|---|
| `script/VerifyLaunch.s.sol` | the check, from `script/shield/SettleLaunch.s.sol` `verifyOnly()` |
| `contracts/shield/...` | the proof reader `RealQueryVerify` and its eight imports, unmodified |
| `vectors/route2.*` | the public vector `wallet-vectors/transfer-eth` proved by the route-2 package: accepted |
| `vectors/pre-route2.*` | the same vector proved by the prover vendored before route 2: refused, `MaskSlotNotZero(0)` |
| `lib/forge-std` | forge-std at `f494b0c2c045dda3df3d761bc82209b9a015c4e7` |

Source: NOX-SmartContract, launch pool `0x8e377752C8890E23A1E9F40eBbD41183Fc6949e2`, Foundry 1.5.0,
solc 0.8.24. Change nothing here; a new kit comes from the pool team with new hashes.
