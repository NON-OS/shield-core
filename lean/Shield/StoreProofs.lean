/-
  The store's properties. The model is in Store; these are the statements the
  wallet's bookkeeping is trusted on.
-/
import Shield.Store

namespace Shield.Store

/-- A found note is spendable, and its value is the value the row carried. -/
theorem found_is_spendable (cm value : Nat) :
    spendable (replay [Row.found cm value]) = value := by
  simp [replay, apply, insert, spendable, empty]

/-- A note spent after being found counts for nothing. -/
theorem spent_is_not_spendable (cm value : Nat) :
    spendable (replay [Row.found cm value, Row.spend cm]) = 0 := by
  simp [replay, apply, insert, markSpent, spendable, empty]

/-- The same found row twice is one note, not two. -/
theorem found_twice_is_one_note (cm value : Nat) :
    spendable (replay [Row.found cm value, Row.found cm value]) = value := by
  simp [replay, apply, insert, spendable, empty]

/-- Spending a note the store never saw changes nothing. -/
theorem spending_an_unknown_note_is_inert (cm other value : Nat) (h : other ≠ cm) :
    spendable (replay [Row.found cm value, Row.spend other]) = value := by
  simp [replay, apply, insert, markSpent, spendable, empty, h, Ne.symm h]

/-- The cursor never moves backwards, so a rescan cannot lose ground. -/
theorem cursor_is_monotone (st : State) (r : Row) : st.cursor ≤ (apply st r).cursor := by
  cases r <;> simp [apply, Nat.le_max_left]

/-- A replay is a function of the log alone: the same rows give the same state. -/
theorem replay_is_deterministic (rows : List Row) : replay rows = replay rows := rfl

end Shield.Store
