#!/usr/bin/env bash
# Nothing generates, stores or sends a unique identifier.
#
# Not a device id, not an install id, not a session id that outlives a request.
# An identifier is how traffic that reveals nothing on its own becomes a
# profile, and the wallet's requests are meant to be indistinguishable from
# each other.
set -euo pipefail

cd "$(dirname "$0")/.."

# The names an identifier arrives under, and the platform calls that hand one
# out. Uuid and Ulid cover the crates; the rest are what the platforms offer.
patterns='Uuid|uuid|Ulid|install_id|device_id|deviceId|client_id|clientId|session_id|sessionId|advertising|IDFA|IDFV|identifierForVendor|ANDROID_ID|getDeviceId|Settings\.Secure'

offenders=$(grep -rnE "$patterns" core/src field-kernel/src --include='*.rs' || true)
if [ -n "$offenders" ]; then
    echo "identifier surface in code that ships:" >&2
    echo "$offenders" >&2
    exit 1
fi

# The one place randomness is drawn is the entropy module, and every draw there
# is a key, a blinding or a nonce. A new caller has to be visible. notes/xwing.rs
# draws the 64 bytes of X-Wing encapsulation randomness, fresh for every note:
# an ephemeral, used once, never stored or sent as itself. prover/launch/
# entropy.rs draws the 512 bytes the launch prover turns into the created
# notes' blindings and the proof's own blinding, spent once per proof.
# wallet/watch/file.rs draws the 12-byte nonce each time the file of view keys
# is sealed again, used once and written beside its ciphertext.
callers=$(grep -rln "entropy::fill\|use crate::entropy\|use super::fill" core/src --include='*.rs' | sort)
expected="core/src/custody/mnemonic.rs
core/src/custody/vault/store.rs
core/src/entropy/seed.rs
core/src/notes/blinding.rs
core/src/notes/cipher/seal.rs
core/src/notes/xwing.rs
core/src/prover/launch/entropy.rs
core/src/wallet/watch/file.rs"
if [ "$(echo "$callers" | sort)" != "$(echo "$expected" | sort)" ]; then
    echo "the set of callers that draw randomness changed:" >&2
    diff <(echo "$expected" | sort) <(echo "$callers") >&2 || true
    echo "every draw is a key, a blinding or a nonce. If this is a new one," >&2
    echo "say which in the commit and update this list." >&2
    exit 1
fi

echo "no identifier, and randomness is drawn in $(echo "$callers" | wc -l | tr -d ' ') accounted places"
