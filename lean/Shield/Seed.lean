/-
  The blinding seed is used once.

  Two hidden proofs of one statement under one seed carry the same blinding, so
  their openings subtract to the witness. The core refuses a seed it has
  already spent; this is that rule as a state machine, and the proof that the
  second attempt cannot succeed.
-/
namespace Shield.Seed

/-- A seed, identified by its digest, which is what the core records. -/
abbrev Digest := Nat

/-- What the core answers when a seed is offered. -/
inductive Outcome where
  | accepted
  | refused
  deriving DecidableEq, Repr

/-- The seeds already spent in this process. -/
abbrev Spent := List Digest

/-- Offer a seed: accepted once, and recorded, or refused. -/
def offer (spent : Spent) (d : Digest) : Outcome × Spent :=
  if d ∈ spent then (Outcome.refused, spent) else (Outcome.accepted, d :: spent)

/-- A seed that has not been spent is accepted. -/
theorem fresh_accepted (spent : Spent) (d : Digest) (h : d ∉ spent) :
    (offer spent d).1 = Outcome.accepted := by
  simp [offer, h]

/-- Offering a seed records it. -/
theorem accepted_records (spent : Spent) (d : Digest) (h : d ∉ spent) :
    d ∈ (offer spent d).2 := by
  simp [offer, h]

/-- The same seed offered a second time is refused. -/
theorem second_offer_refused (spent : Spent) (d : Digest) :
    (offer (offer spent d).2 d).1 = Outcome.refused := by
  by_cases h : d ∈ spent
  · simp [offer, h]
  · simp [offer, h]

/-- A refusal never changes the record, so a refused attempt leaves no trace. -/
theorem refused_keeps_record (spent : Spent) (d : Digest) (h : d ∈ spent) :
    (offer spent d).2 = spent := by
  simp [offer, h]

end Shield.Seed
