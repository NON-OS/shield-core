import Aeneas
import NoxVerified

/-!
# The balance of a transfer

Proved about `verified/src/transfer.rs` itself, through Aeneas, not about a
model. The core's `plan_send` chooses the two notes and calls `balance` for the
arithmetic, so the equation a transfer must satisfy is proved about the code
that computes it.

Everything is machine bounded: `U64` is a 64 bit bitvector and every operation
is the checked one, returning nothing rather than wrapping.
-/

open Aeneas Aeneas.Std Result Aeneas.Std.WP
open NoxVerified

namespace NoxVerified

/-- **What goes in equals what comes out.** Whenever `balance` returns a
change, the two notes spent are exactly the amount, the fee and that change,
as numbers, with no wrap anywhere. This is the equation that keeps a transfer
from creating or destroying gwei. -/
theorem the_transfer_balances (first second amount fee : U64) :
    transfer.balance first second amount fee
      ⦃ result => ∀ needed change, result = some (needed, change) →
          first.val + second.val = amount.val + fee.val + change.val ∧
          needed.val = amount.val + fee.val ⦄ := by
  unfold transfer.balance
  step*

/-- **A pair that covers the amount is never refused.** If the two notes add
up to at least the amount and the fee, and their sum fits, `balance` answers
with a change rather than nothing. The core chooses such a pair, so this is
what makes a refusal mean the wallet really cannot pay. -/
theorem a_covering_pair_is_never_refused (first second amount fee : U64)
    (fits : first.val + second.val < 2 ^ 64)
    (covers : amount.val + fee.val ≤ first.val + second.val) :
    transfer.balance first second amount fee ⦃ result => result ≠ none ⦄ := by
  unfold transfer.balance
  step*

/-- **A pair that does not cover the amount is refused**, not paid short. -/
theorem an_uncovered_pair_is_refused (first second amount fee : U64)
    (short : first.val + second.val < amount.val + fee.val) :
    transfer.balance first second amount fee ⦃ result => result = none ⦄ := by
  unfold transfer.balance
  step*

end NoxVerified
