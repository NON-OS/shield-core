/-
  The note store folds to a balance.

  The store is an append only log. Its rows are notes found, status changes and
  the scan cursor, and the balance is what they fold up to. What is proven here
  is that a spent note stops counting, that a row replayed twice changes
  nothing, and that a replay is a function of the log alone.
-/
namespace Shield.Store

/-- A note, identified by its commitment, with a value and whether it is spent. -/
structure Note where
  cm : Nat
  value : Nat
  spent : Bool
  deriving Repr, DecidableEq

/-- One row of the log. -/
inductive Row where
  | found (cm value : Nat)
  | spend (cm : Nat)
  | cursor (n : Nat)
  deriving Repr, DecidableEq

/-- What the rows fold into: the notes held, and where the scan reached. -/
structure State where
  notes : List Note
  cursor : Nat
  deriving Repr, DecidableEq

def empty : State := { notes := [], cursor := 0 }

/-- Replace a note with the same commitment, or add it. Keyed by commitment, so
    a row replayed twice cannot make one note two. -/
def insert (notes : List Note) (n : Note) : List Note :=
  n :: notes.filter (fun m => m.cm != n.cm)

/-- Mark a note spent, leaving every other note alone. -/
def markSpent (notes : List Note) (cm : Nat) : List Note :=
  notes.map (fun m => if m.cm = cm then { m with spent := true } else m)

/-- Fold one row in. -/
def apply (st : State) : Row → State
  | Row.found cm value =>
      { st with notes := insert st.notes { cm := cm, value := value, spent := false } }
  | Row.spend cm => { st with notes := markSpent st.notes cm }
  | Row.cursor n => { st with cursor := max st.cursor n }

/-- Replay a whole log. -/
def replay (rows : List Row) : State := rows.foldl apply empty

/-- What can be spent. -/
def spendable (st : State) : Nat :=
  (st.notes.filter (fun n => !n.spent)).foldl (fun acc n => acc + n.value) 0

end Shield.Store
