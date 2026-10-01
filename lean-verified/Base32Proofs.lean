import Aeneas
import NoxVerified

/-!
# The address alphabet

Proved about `verified/src/base32.rs` and `verified/src/base32_tail.rs`
themselves, through Aeneas, not about a model. The core's encoder and decoder
walk an address five bytes at a time and call these functions for every group
and for the three byte tail, so what is proved here is what an address is.

Everything is machine bounded: every arithmetic step is Rust's and fails on
overflow or on a zero divisor, every cast is Rust's, and every array index is
checked. A Hoare triple here says the function returns, and what it returns.
-/

open Aeneas Aeneas.Std Result Aeneas.Std.WP
open NoxVerified

set_option maxHeartbeats 8000000

namespace NoxVerified

/-- **A symbol has one glyph, and that glyph reads back as the symbol.** -/
theorem a_glyph_reads_back_as_its_symbol (v : U8) (h : v.val < 32) :
    base32.glyph v ⦃ g => ∀ c, g = some c → base32.value c ⦃ r => r = some v ⦄ ⦄ := by
  unfold base32.glyph
  step*
  · intro c hc; unfold base32.value; step* <;> simp only [Option.some.injEq] at * <;> subst_vars <;> scalar_tac
  · intro c hc; unfold base32.value; step* <;> simp only [Option.some.injEq] at * <;> subst_vars <;> scalar_tac

/-- **A glyph that reads as a symbol is the glyph that symbol writes.** With the
theorem above this makes the alphabet a bijection between the 32 symbols and
the 32 characters, and nothing else reads as anything. -/
theorem a_symbol_writes_the_glyph_that_read_it (c : U8) :
    base32.value c ⦃ r => ∀ v, r = some v → base32.glyph v ⦃ g => g = some c ⦄ ⦄ := by
  unfold base32.value
  step*
  · intro v hv; unfold base32.glyph; step* <;> simp only [Option.some.injEq] at * <;> subst_vars <;> scalar_tac
  · intro v hv; unfold base32.glyph; step* <;> simp only [Option.some.injEq] at * <;> subst_vars <;> scalar_tac

/-- The eight or five symbols of a group as named elements, so that every
index into the group is a name rather than a lookup. -/
macro "open_group" b:ident : tactic => `(tactic| (
  obtain ⟨l, hl⟩ := $b
  rcases l with _ | ⟨x0, _ | ⟨x1, _ | ⟨x2, _ | ⟨x3, _ | ⟨x4, _ | ⟨x5, _ | ⟨x6, _ | ⟨x7, _ | ⟨x8, l⟩⟩⟩⟩⟩⟩⟩⟩⟩ <;> simp at hl))

/-- After `step*`: the group literals are opened, every cast is a value, and
what is left is the arithmetic of digits, which `scalar_tac` settles. -/
macro "digits" : tactic => `(tactic| (
  subst_vars
  try simp only [Array.make, List.getElem_cons_zero, List.getElem_cons_succ,
    List.getElem!_cons_zero, List.getElem!_cons_succ, Option.some.injEq] at *
  try subst_vars
  try simp only [Array.make, List.getElem_cons_zero, List.getElem_cons_succ,
    List.getElem!_cons_zero, List.getElem!_cons_succ, Option.some.injEq] at *
  try simp only [U8.cast_U64_val_eq] at *
  try simp only [UScalar.cast_val_eq, UScalarTy.U8_numBits_eq, UScalarTy.U64_numBits_eq] at *
  first
  | (exfalso; scalar_tac)
  | (apply Subtype.ext; simp only [List.cons.injEq, and_true]; and_intros <;> scalar_tac)
  | scalar_tac))

/-- **Five bytes survive the round trip.** Encoding to eight symbols and
decoding gives the bytes back, for every one of the 2^40 groups, and neither
direction can fail. -/
theorem five_bytes_survive_the_round_trip (b : Array U8 5#usize) :
    (do
      let s ← base32.encode5 b
      base32.decode5 s) ⦃ r => r = some b ⦄ := by
  open_group b
  unfold base32.encode5 base32.decode5
  step* <;> digits

/-- **Eight symbols that decode are exactly what their bytes encode.** There is
one spelling of five bytes: any eight symbols the decoder accepts are the eight
the encoder writes for the bytes it returns. -/
theorem five_bytes_have_one_spelling (s : Array U8 8#usize) :
    base32.decode5 s ⦃ r => ∀ b, r = some b → base32.encode5 b ⦃ t => t = s ⦄ ⦄ := by
  open_group s
  unfold base32.decode5
  step*
  intro b hb
  unfold base32.encode5
  step* <;> digits

/-- **Three bytes survive the round trip** through the five symbol tail. -/
theorem three_bytes_survive_the_round_trip (b : Array U8 3#usize) :
    (do
      let s ← base32_tail.encode3 b
      base32_tail.decode3 s) ⦃ r => r = some b ⦄ := by
  open_group b
  unfold base32_tail.encode3 base32_tail.decode3
  step* <;> digits

/-- **A set padding bit is refused.** The twenty fifth bit of the tail is
padding; the encoder writes it as zero and the decoder refuses it set, which is
what leaves an address with one spelling rather than two. -/
theorem a_set_padding_bit_is_refused (s : Array U8 5#usize)
    (odd : (s.val[4]!).val % 2 = 1) :
    base32_tail.decode3 s ⦃ r => r = none ⦄ := by
  open_group s
  unfold base32_tail.decode3
  step* <;> digits

/-- **Five tail symbols that decode are exactly what their bytes encode.** -/
theorem three_bytes_have_one_spelling (s : Array U8 5#usize) :
    base32_tail.decode3 s ⦃ r => ∀ b, r = some b → base32_tail.encode3 b ⦃ t => t = s ⦄ ⦄ := by
  open_group s
  unfold base32_tail.decode3
  step*
  intro b hb
  unfold base32_tail.encode3
  step* <;> digits

end NoxVerified
