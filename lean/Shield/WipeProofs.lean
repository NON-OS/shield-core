/-
  What destroying a wallet leaves behind, in the store's own model.

  The wipe overwrites and removes the log, and the platform key that seals it
  goes with it. Neither of those is something this model can talk about: they
  are files and a keystore. What the model can say is what the balance is
  worth if the removal is incomplete, which is the case worth proving because
  it is the one nobody controls. A flash controller may keep blocks a
  filesystem has forgotten, and a truncated log may leave rows behind.

  So: a log with no found row in it is worth nothing, whatever else survives.
  Status rows and cursor rows cannot introduce value, and an empty log folds
  to the empty state.
-/
import Shield.Store

namespace Shield.Store

/-- Whether a row can introduce a note. Only a found row carries value. -/
def isFound : Row → Bool
  | Row.found _ _ => true
  | Row.spend _ => false
  | Row.cursor _ => false

/-- Folding rows that cannot introduce a note leaves the notes as they were
    found: empty. Stated over any starting state so the induction can carry
    the hypothesis through the fold. -/
theorem fold_keeps_notes_empty (rows : List Row) :
    ∀ st : State, st.notes = [] → (∀ r ∈ rows, isFound r = false) →
      (rows.foldl apply st).notes = [] := by
  induction rows with
  | nil => intro st hs _; simpa using hs
  | cons r rest ih =>
    intro st hs hall
    have hr : isFound r = false := hall r List.mem_cons_self
    have hrest : ∀ x ∈ rest, isFound x = false := by
      intro x hx
      exact hall x (List.mem_cons_of_mem r hx)
    refine ih (apply st r) ?_ hrest
    cases r with
    | found cm value => simp [isFound] at hr
    | spend cm => simp [apply, markSpent, hs]
    | cursor n => simp [apply, hs]

/-- A log that survives a wipe without any found row in it is worth nothing.
    This is the property the destruction relies on when removal is partial. -/
theorem a_log_with_no_found_row_is_worth_nothing (rows : List Row)
    (h : ∀ r ∈ rows, isFound r = false) : spendable (replay rows) = 0 := by
  have hn : (replay rows).notes = [] := fold_keeps_notes_empty rows empty rfl h
  simp [spendable, hn]

/-- The log being gone entirely is the same as never having had one. -/
theorem a_wiped_store_is_the_empty_store : replay [] = empty := rfl

/-- And it has nothing to spend. -/
theorem a_wiped_store_has_nothing_to_spend : spendable (replay []) = 0 := by
  simp [replay, spendable, empty]

end Shield.Store
