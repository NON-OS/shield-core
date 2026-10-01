import Aeneas
import NoxVerified

/-!
# The arithmetic under every amount a screen shows or reads

Proved about `verified/src/amount.rs` itself, through Aeneas, not about a model.
The core's `format_amount` and `parse_amount` call these two functions for the
division and the multiplication and add only the text around them.

Everything is machine bounded: `U64` is a 64 bit bitvector, the division and
the remainder are Rust's and fail on a zero divisor, and the multiplication and
the addition are the checked ones that return nothing rather than wrap.
-/

open Aeneas Aeneas.Std Result Aeneas.Std.WP
open NoxVerified

namespace NoxVerified

/-- **The fraction never carries.** Whatever the base units, the second number
`split` returns is below the scale, so a screen printing it in nine places
never has a tenth to lose. -/
@[step]
theorem split_fraction_is_below_the_scale (units : U64) :
    amount.split units ⦃ parts => parts.2.val < 1000000000000000000 ⦄ := by
  unfold amount.split amount.SCALE
  step*

/-- **Splitting and recombining returns the base units it started as**, for every
value a `u64` can hold. This is what makes it safe for a screen to show a
balance as a decimal and read one back: nothing is lost in either direction,
and neither direction can fail. -/
@[step]
theorem split_then_combine_is_the_identity (units : U64) :
    (do
      let parts ← amount.split units
      amount.combine parts.1 parts.2) ⦃ result => result = some units ⦄ := by
  unfold amount.split amount.combine amount.SCALE
  step*
  /-
   * The multiplication was stepped through because it is bound in the monad.
   * The addition is a pure call inside the final `ok`, so its specification
   * is brought in by hand and the two outcomes are split: a sum that fits is
   * the base units by the division identity, and a sum that does not fit cannot
   * happen because that sum is the base units, which fits by construction.
   -/
  have hadd := U64.checked_add_bv_spec scaled x
  cases hz : U64.checked_add scaled x <;> simp_all <;> scalar_tac

/-- **A fraction that would carry is refused**, not folded into the whole. A
person who typed ten digits after the point does not get a bigger balance. -/
theorem combine_refuses_a_carrying_fraction (whole fraction : U64)
    (h : fraction.val ≥ 1000000000000000000) :
    amount.combine whole fraction ⦃ result => result = none ⦄ := by
  unfold amount.combine amount.SCALE
  step*

end NoxVerified
