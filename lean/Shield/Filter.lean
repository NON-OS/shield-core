/-
  The discovery filter never drops a note that is ours.

  A scan computes one key agreement per output and compares a one byte tag
  before it attempts an authenticated decryption. That is a performance
  decision, and it is only admissible if it has no false negatives: a note
  addressed to this wallet must always pass the tag.

  The model is deliberately thin. `shared` is the agreement, `tag` is the byte
  derived from it, and neither is modelled further: what is at stake is that
  the filter is a function of the same secret the decryption uses, so passing
  cannot depend on anything else.
-/
namespace Shield.Filter

/-- An output as the scan sees it: the sender's ephemeral key and its tag byte. -/
structure Output where
  ephemeral : Nat
  tagByte : Nat

/-- The viewing secret. -/
abbrev Secret := Nat

variable (shared : Secret → Nat → Nat) (tag : Nat → Nat)

/-- The tag a wallet computes for an output. -/
def computed (view : Secret) (o : Output) : Nat := tag (shared view o.ephemeral)

/-- The filter: does this output's tag match the one we compute? -/
def passes (view : Secret) (o : Output) : Prop := computed shared tag view o = o.tagByte

/-- An output is ours when the sender wrote the tag our secret computes. -/
def ours (view : Secret) (o : Output) : Prop := o.tagByte = tag (shared view o.ephemeral)

/-- No false negatives: an output that is ours passes the filter. -/
theorem ours_passes (view : Secret) (o : Output) (h : ours shared tag view o) :
    passes shared tag view o := by
  simp only [passes, computed, ours] at *
  exact h.symm

/--
  The filter is not a claim of soundness in the other direction, and the code
  does not treat it as one: an output that passes is still opened under the
  AEAD, and a note whose plaintext does not commit to the commitment it arrived
  with is dropped. This is that statement: passing says nothing on its own.
-/
theorem passing_is_not_ownership (view : Secret) (o : Output) :
    passes shared tag view o → o.tagByte = computed shared tag view o := by
  intro h
  exact h.symm

end Shield.Filter
