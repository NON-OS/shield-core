import Aeneas
import NoxVerified

/-!
# The money arithmetic of a public send

Proved about `verified/src/fee.rs` itself, through Aeneas, not about a model.
The core calls these four functions for the token fee taken from a send, the
fee a send offers the network, the nonce it signs, and the check that the
balance covers the amount and the most the fee can be.

Everything is machine bounded: `U128` and `U64` are bitvectors, the division is
Rust's and fails on a zero divisor, and the multiplication and the addition are
the checked ones that return nothing rather than wrap.
-/

open Aeneas Aeneas.Std Result Aeneas.Std.WP
open NoxVerified

namespace NoxVerified

/-- **What arrives and the fee add back to the amount.** Whenever `split_fee`
answers, the fee is the amount times the rate in basis points, rounded down,
it is below the amount, and the two parts add up to the amount with no wrap. -/
theorem the_token_fee_adds_back (amount : U128) (bps : U16) :
    fee.split_fee amount bps
      ⦃ result => ∀ arrives taken, result = some (arrives, taken) →
          arrives.val + taken.val = amount.val ∧
          taken.val = amount.val * bps.val / 10000 ∧
          taken.val < amount.val ⦄ := by
  unfold fee.split_fee fee.BPS
  step*

/-- **A fee that would take the whole amount is refused**, never sent as a
transfer of nothing. -/
theorem a_fee_of_the_whole_is_refused (amount : U128) (bps : U16)
    (all : amount.val ≤ amount.val * bps.val / 10000) :
    fee.split_fee amount bps ⦃ result => result = none ⦄ := by
  unfold fee.split_fee fee.BPS
  step*

/-- **The offer stays under the ceiling.** Whenever `offer` answers, the tip is
at most 5 gwei and at most what was suggested, and the cap is twice the base
fee plus the tip and at most 1,000 gwei, so a lying RPC cannot raise it. -/
theorem the_offer_is_held_to_the_ceiling (base suggested : U128) :
    fee.offer base suggested
      ⦃ result => ∀ tip cap, result = some (tip, cap) →
          tip.val ≤ 5000000000 ∧ tip.val ≤ suggested.val ∧
          cap.val = 2 * base.val + tip.val ∧ cap.val ≤ 1000000000000 ⦄ := by
  unfold fee.offer fee.MAX_TIP fee.CEILING
  split <;> step*

/-- **A base fee past the ceiling gets no offer at all**, so nothing is signed
at a price the wallet would never pay. -/
theorem an_offer_past_the_ceiling_is_refused (base suggested : U128)
    (past : 1000000000000 < 2 * base.val) :
    fee.offer base suggested ⦃ result => result = none ⦄ := by
  unfold fee.offer fee.MAX_TIP fee.CEILING
  split <;> step*

/-- **A send never reuses a nonce.** The nonce is the larger of the pending
count and the one past every recorded send, and it is one of the two. -/
theorem the_nonce_is_the_larger (pending recorded : U64) :
    fee.next_nonce pending recorded
      ⦃ n => pending.val ≤ n.val ∧ recorded.val ≤ n.val ∧ (n = pending ∨ n = recorded) ⦄ := by
  unfold fee.next_nonce
  step*

/-- **The balance covers exactly the sums that fit it.** `covers` answers yes
when the amount and the fee add up to at most the balance, as numbers, and no
when they do not, with no wrapped sum small enough to pass. -/
theorem covers_is_the_true_sum (balance amount taken : U128) :
    fee.covers balance amount taken
      ⦃ yes => yes = true ↔ amount.val + taken.val ≤ balance.val ⦄ := by
  unfold fee.covers
  step*

end NoxVerified
