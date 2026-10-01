/-
  The amount codec, as arithmetic.

  A note's value is a 64 bit number of gwei, and a screen shows it with a
  decimal point nine places from the right. The shells do none of this: the
  core splits and joins, and what is proven here is that the split and the join
  are inverse, so a number shown to a user and read back is the same number.
-/
namespace Shield.Amount

/-- Gwei per unit: nine decimal places. -/
def scale : Nat := 1000000000

/-- The two halves a screen shows: whole units, and gwei below one unit. -/
def toParts (n : Nat) : Nat × Nat := (n / scale, n % scale)

/-- The number those halves stand for. -/
def ofParts (p : Nat × Nat) : Nat := p.1 * scale + p.2

/-- Formatting then reading gives back the amount. -/
theorem ofParts_toParts (n : Nat) : ofParts (toParts n) = n := by
  simp only [ofParts, toParts, scale]
  omega

/-- The fractional half is always below one whole unit, so it never carries. -/
theorem fraction_lt_scale (n : Nat) : (toParts n).2 < scale := by
  simp only [toParts, scale]
  omega

/-- Reading then formatting gives back the halves, for halves a screen can show. -/
theorem toParts_ofParts (w f : Nat) (h : f < scale) : toParts (ofParts (w, f)) = (w, f) := by
  simp only [toParts, ofParts, scale, Prod.mk.injEq] at *
  omega

/--
  An amount that fits 64 bits stays inside it after a round trip. The wallet
  refuses an out of range amount at the edge, and this is the statement that the
  codec itself adds nothing.
-/
theorem round_trip_in_range (n : Nat) (h : n < 2 ^ 64) : ofParts (toParts n) < 2 ^ 64 := by
  rw [ofParts_toParts]
  exact h

end Shield.Amount
