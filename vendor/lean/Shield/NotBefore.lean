-- NONOS Operating System (AGPL-3.0-or-later)
import Shield.Intent

/-!
The earliest settlement time, word 36 of the transfer statement in the
`not_before` build (shield/join/publics.rs).

The statement is the thirty-two words of `Shield.Intent`, the fee recipient's
four, then `not_before`: thirty-seven. The first thirty-six are the statement
without the time, unchanged, so the new word moves nothing a verifier already
reads. The time sits on a 600-second grid and is never zero; a wallet rounds
its drawn delay up to the next grid point, which is never earlier than the
draw and less than one grid step later.

`stark_proofs/src/shield/test/not_before_lean_test.rs` reads the three constants
below out of this file and compares them with the Rust ones.
-/

namespace Shield.NotBefore

open Shield.Intent

def positionOfFeeRecipient : Nat := 32
def positionOfNotBefore : Nat := 36
def grid : Nat := 600

/-- the statement with the time, in the order `Intent::words` emits it -/
def words (i : Intent) (feeRecipient : Digest) (notBefore : Nat) : List Nat :=
  Intent.words i ++ feeRecipient.words ++ [notBefore]

theorem the_statement_is_thirty_seven_words (i : Intent) (f : Digest) (t : Nat) :
    (words i f t).length = 37 := by
  simp [words, Intent.words, Digest.words, the_intent_is_thirty_two_words]

theorem the_fee_recipient_follows_the_intent :
    positionOfRecipient + 4 = positionOfFeeRecipient := rfl

theorem the_time_follows_the_fee_recipient :
    positionOfFeeRecipient + 4 = positionOfNotBefore := rfl

theorem the_time_is_word_36 (i : Intent) (f : Digest) (t : Nat) :
    nth (words i f t) positionOfNotBefore = some t := by
  cases i; cases f
  rfl

theorem the_fee_recipient_sits_at_32 (i : Intent) (f : Digest) (t : Nat) :
    digestAt (words i f t) positionOfFeeRecipient = f.words := by
  cases i; cases f
  rfl

/-- the first thirty-six words do not depend on the time -/
theorem the_time_moves_nothing_before_it (i : Intent) (f : Digest) (t u : Nat) :
    (words i f t).take 36 = (words i f u).take 36 := by
  cases i; cases f
  rfl

/-- two times give two statements: a proof for one is a proof of another claim -/
theorem another_time_is_another_statement (i : Intent) (f : Digest) (t u : Nat)
    (h : t ≠ u) : words i f t ≠ words i f u := by
  intro e
  apply h
  have := congrArg (fun l => nth l positionOfNotBefore) e
  simpa [the_time_is_word_36] using this

/-- the rule `host/spend.rs` refuses a request by -/
def onGrid (t : Nat) : Prop := t ≠ 0 ∧ t % grid = 0

instance (t : Nat) : Decidable (onGrid t) := by
  unfold onGrid; exact inferInstance

/-- the wallet's rounding: the next grid point at or after `t` -/
def roundUp (t : Nat) : Nat := (t + grid - 1) / grid * grid

theorem roundUp_on_the_grid (t : Nat) : roundUp t % grid = 0 := by
  simp [roundUp, grid, Nat.mul_mod_left]

theorem roundUp_not_earlier (t : Nat) : t ≤ roundUp t := by
  simp only [roundUp, grid]
  omega

theorem roundUp_within_one_step (t : Nat) : roundUp t < t + grid := by
  simp only [roundUp, grid]
  omega

theorem roundUp_of_positive (t : Nat) (h : 0 < t) : onGrid (roundUp t) := by
  refine ⟨?_, roundUp_on_the_grid t⟩
  have := roundUp_not_earlier t
  omega

/-- the pinned set's time, and the neighbours the tamper test tries -/
theorem the_pinned_time_is_on_the_grid : onGrid 1790000400 := by decide
theorem one_second_off_is_refused : ¬ onGrid 1790000401 := by decide
theorem zero_is_refused : ¬ onGrid 0 := by decide

end Shield.NotBefore
