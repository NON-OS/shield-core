-- NONOS Operating System (AGPL-3.0-or-later)
import Shield.NotBefore

/-!
The claim statement (`claim` build, shield/join/publics.rs): the thirty-six
words of the transfer, then the two input notes' limb sums, low then high.

A note's value is two limbs, `v = lo + 2^32 * hi`, with `lo < 2^32` and
`hi ≤ 2^32 - 2` (the balance region's range cells). The balance region keeps
the low and the high limbs in separate running sums, so after the two input
legs it holds `lo₀ + lo₁` and `hi₀ + hi₁`, and no cell holds the total. The
statement carries both sums, and the pool rebuilds the total.

What is proved:
- the statement is thirty-eight words, the sums at 36 and 37, the first
  thirty-six untouched;
- the sums rebuild the inputs' total exactly;
- an honest claim passes the pool's range check (both sums below 2^33), so the
  check refuses only what the circuit could never produce.

`stark_proofs/src/shield/test/claim_lean_test.rs` reads the three constants
below out of this file and compares them with the Rust ones.
-/

namespace Shield.Claim

open Shield.Intent

def positionOfInputSumLo : Nat := 36
def positionOfInputSumHi : Nat := 37
def limbShift : Nat := 4294967296

/-- the statement, in the order `Intent::words` emits it -/
def words (i : Intent) (feeRecipient : Digest) (lo hi : Nat) : List Nat :=
  Intent.words i ++ feeRecipient.words ++ [lo, hi]

theorem the_statement_is_thirty_eight_words (i : Intent) (f : Digest) (lo hi : Nat) :
    (words i f lo hi).length = 38 := by
  simp [words, Intent.words, Digest.words, the_intent_is_thirty_two_words]

theorem the_sums_follow_the_fee_recipient :
    Shield.NotBefore.positionOfFeeRecipient + 4 = positionOfInputSumLo ∧
    positionOfInputSumLo + 1 = positionOfInputSumHi := ⟨rfl, rfl⟩

theorem the_low_sum_is_word_36 (i : Intent) (f : Digest) (lo hi : Nat) :
    nth (words i f lo hi) positionOfInputSumLo = some lo := by
  cases i; cases f
  rfl

theorem the_high_sum_is_word_37 (i : Intent) (f : Digest) (lo hi : Nat) :
    nth (words i f lo hi) positionOfInputSumHi = some hi := by
  cases i; cases f
  rfl

theorem the_sums_move_nothing_before_them (i : Intent) (f : Digest) (lo hi lo' hi' : Nat) :
    (words i f lo hi).take 36 = (words i f lo' hi').take 36 := by
  cases i; cases f
  rfl

/-- the total the pool rebuilds from the two words -/
def total (lo hi : Nat) : Nat := lo + limbShift * hi

/-- the two sums rebuild the sum of the two values, whatever the limbs -/
theorem the_sums_rebuild_the_total (lo₀ hi₀ lo₁ hi₁ : Nat) :
    total (lo₀ + lo₁) (hi₀ + hi₁) = total lo₀ hi₀ + total lo₁ hi₁ := by
  simp only [total, limbShift]
  omega

/-- an honest claim is never refused by the pool's range check -/
theorem an_honest_claim_is_in_range (lo₀ hi₀ lo₁ hi₁ : Nat)
    (hl₀ : lo₀ < limbShift) (hl₁ : lo₁ < limbShift)
    (hh₀ : hi₀ ≤ limbShift - 2) (hh₁ : hi₁ ≤ limbShift - 2) :
    lo₀ + lo₁ < 2 * limbShift ∧ hi₀ + hi₁ < 2 * limbShift := by
  simp only [limbShift] at *
  omega

/-- two different pairs are two statements, even with the same total -/
theorem another_pair_is_another_statement (i : Intent) (f : Digest) (lo hi lo' hi' : Nat)
    (h : lo ≠ lo' ∨ hi ≠ hi') : words i f lo hi ≠ words i f lo' hi' := by
  intro e
  rcases h with h | h
  · apply h
    have := congrArg (fun l => nth l positionOfInputSumLo) e
    simpa [the_low_sum_is_word_36] using this
  · apply h
    have := congrArg (fun l => nth l positionOfInputSumHi) e
    simpa [the_high_sum_is_word_37] using this

end Shield.Claim
