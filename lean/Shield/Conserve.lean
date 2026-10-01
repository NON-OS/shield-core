/-
  Value conservation, which is the property the circuit enforces and the
  planner has to respect before it ever builds a witness.

  A transfer spends two notes and creates two, pays a fee and may move an
  amount publicly. Conservation is one equation, and the planner's change
  calculation is the only freedom it has.
-/
namespace Shield.Conserve

/-- The values a transfer moves. -/
structure Transfer where
  inA : Nat
  inB : Nat
  outA : Nat
  outB : Nat
  publicAmount : Nat
  fee : Nat

/-- What the circuit checks: nothing is created and nothing vanishes. -/
def balanced (t : Transfer) : Prop :=
  t.inA + t.inB = t.outA + t.outB + t.publicAmount + t.fee

/--
  The plan the wallet builds: the recipient gets the amount, the change comes
  back, the fee is paid, and nothing moves publicly.
-/
def plan (a b amount fee : Nat) : Transfer :=
  { inA := a
    inB := b
    outA := amount
    outB := a + b - amount - fee
    publicAmount := 0
    fee := fee }

/-- A plan over notes that cover the amount and the fee is balanced. -/
theorem plan_balanced (a b amount fee : Nat) (h : amount + fee ≤ a + b) :
    balanced (plan a b amount fee) := by
  simp only [balanced, plan]
  omega

/-- A balanced transfer never creates value. -/
theorem no_mint (t : Transfer) (h : balanced t) : t.outA + t.outB ≤ t.inA + t.inB := by
  simp only [balanced] at h
  omega

/-- The change is exactly what is left, so a plan loses nothing to rounding. -/
theorem change_is_remainder (a b amount fee : Nat) (h : amount + fee ≤ a + b) :
    (plan a b amount fee).outB + amount + fee = a + b := by
  simp only [plan]
  omega

/--
  A transfer that does not cover its fee has no balanced plan. The wallet
  refuses at the planner rather than building a witness no proof exists for.
-/
theorem uncovered_has_no_plan (a b amount fee : Nat) (h : a + b < amount + fee) :
    ¬ balanced { inA := a, inB := b, outA := amount, outB := 0,
                 publicAmount := 0, fee := fee } := by
  simp only [balanced]
  omega

end Shield.Conserve
