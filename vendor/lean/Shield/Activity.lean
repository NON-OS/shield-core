-- NONOS Operating System (AGPL-3.0-or-later)

/-!
The activity statement (`stark_proofs/src/activity`): in week `e`, the holder
of one nullifier key spent `k` different notes whose nullifiers are leaves of
the week's spend root Λ_e. The week's tag is `T` and the payout digest is `P`.

Eighteen public words: Λ_e (0 to 3), `e` (4), `k` (5), `T` (6 to 9), `P` (10 to
13), `K` (14 to 17), the key commitment. Four slots. Each slot is a Poseidon chain of eighteen compressions:

- row 0 is `[nk | cm]`;
- row 32 is `[t | position, live, 0, 0]`, with the live lane and the last two
  pinned to zero, so the nullifier is a live note's and never a dummy's;
- sixteen levels of Λ_e follow, and the walked root sits at row 576.

Level `m`'s direction rides row `32 m - 1`, column 8. Level 1's is pinned to
zero, so the position word is always the right half. The count region holds,
for each slot, a live bit, its position in Λ_e and its walked root, plus three
gaps and `k`.

What is proved here:

- a live bit vector that satisfies the count's rules is live-first and
  counts 1 to 4: `k` live slots are exactly the first `k`;
- `pos' = pos + 1 + gap` in the field, with both positions and the gap below
  2^16, holds over the integers, so live positions strictly increase and
  no spend is counted twice;
- the pins, the directions, the position row and the checkpoint are distinct
  rows of the chain, and the checkpoint is its last compression's output;
- the tag chain's row 0 is the tag's preimage under the wires, and the key
  chain's row 0 is K's: the same `nk` lanes, its own domain, the week lane
  pinned to zero, so K is one per key and T one per key per week;
- the regions fit 2^13 rows and overflow 2^12: the transfer's length, so the
  FRI domain and every round's soundness figure are the transfer's;
- the statement's ranges cover words 0 to 17 without overlap.

`stark_proofs/src/activity/test.rs` reads the constants below out of this file
and holds them equal to the circuit's.
-/

namespace Shield.Activity

def p : Nat := 18446744069414584321

def slots : Nat := 4
def depth : Nat := 16
def rounds : Nat := 32
def words : Nat := 18
def lambda : Nat := 0
def week : Nat := 4
def count : Nat := 5
def tag : Nat := 6
def payout : Nat := 10
def key : Nat := 14
def activityDomain : Nat := 5642825895444239921
def keyDomain : Nat := 5642825895444237105
def gapBits : Nat := 16
def logTrace : Nat := 13

/-- Compressions per slot: `nk | cm`, `t | position`, then Λ_e's levels. -/
def compressions : Nat := 2 + depth
def positionRow : Nat := rounds
def checkpointRow : Nat := compressions * rounds
/-- The direction column of a chain: the column after the eight state lanes. -/
def dirCol : Nat := 8

/-- The row carrying level `m`'s direction. -/
def dirRow (m : Nat) : Nat := m * rounds - 1

/-- `(row, column)`: a slot chain's constant pins, all zero. -/
def pins : List (Nat × Nat) := [(31, 8), (32, 5), (32, 6), (32, 7)]

/-- The rows of Λ_e's sixteen directions, levels 2 to 17. -/
def lambdaDirRows : List Nat := (List.range depth).map fun k => dirRow (k + 2)

/-- The count region's columns. -/
def colLive : Nat := 0
def colPos : Nat := 4
def colGap : Nat := 8
def colK : Nat := 11
def colWalked : Nat := 12
def colRoot : Nat := 28
def countWidth : Nat := 32

/-- Rows of each region, in stack order: four chains, four index scalars, the
count, the gaps' range, the tag chain, the key chain, the statement, padding. -/
def regionRows : List Nat :=
  [608, 608, 608, 608, 32, 32, 32, 32, 2, 49, 64, 64, 32, 4096]

def distinct : List Nat → Bool
  | [] => true
  | x :: xs => !xs.contains x && distinct xs

theorem the_checkpoint_row_is_576 : checkpointRow = 576 := rfl

theorem the_pins_are_level_one's_direction_and_the_position_word's_lanes :
    pins = [(dirRow 1, dirCol), (positionRow, 5), (positionRow, 6), (positionRow, 7)] := rfl

/-- Λ_e's directions are sixteen different rows, none a pinned row, all
before the checkpoint. -/
theorem lambda's_directions_are_their_own_rows :
    distinct lambdaDirRows = true ∧
    lambdaDirRows.all (fun r => !(pins.map (·.1)).contains r) = true ∧
    lambdaDirRows.all (· < checkpointRow) = true := by decide

/-- The last direction is level 17's, the chain's last compression. -/
theorem the_walk_ends_at_the_checkpoint :
    lambdaDirRows.getLast? = some (checkpointRow - 1 - rounds) ∧
    compressions = depth + 2 := ⟨rfl, rfl⟩

/-! ## The count -/

/-- The count's rules on four live bits: live-first, and slot 0 live. -/
def countRules (l : List Bool) : Bool :=
  l.length == slots &&
  l.head? == some true &&
  (l.zip (l.drop 1)).all fun (a, b) => !b || a

def k (l : List Bool) : Nat := (l.filter id).length

def allBits : List (List Bool) :=
  [false, true].flatMap fun a => [false, true].flatMap fun b =>
    [false, true].flatMap fun c => [false, true].map fun d => [a, b, c, d]

/-- Every live vector the rules admit is `k` live slots then dead ones, with
`k` from 1 to 4: the count names exactly the slots it covers. -/
theorem the_live_slots_are_the_first_k :
    allBits.all (fun l => !countRules l ||
      (1 ≤ k l && k l ≤ 4 && l == List.replicate (k l) true ++ List.replicate (4 - k l) false)) = true := by
  decide

theorem there_are_sixteen_vectors : allBits.length = 16 := rfl

/-- The field equation the count enforces between two live neighbours holds
over the integers: both sides are below `p`. -/
theorem the_step_does_not_wrap (a b g : Nat) (ha : a < 2 ^ 16) (hb : b < 2 ^ 16) (hg : g < 2 ^ 16)
    (h : b % p = (a + 1 + g) % p) : b = a + 1 + g := by
  have h1 : b % p = b := Nat.mod_eq_of_lt (by unfold p; omega)
  have h2 : (a + 1 + g) % p = a + 1 + g := Nat.mod_eq_of_lt (by unfold p; omega)
  omega

theorem the_step_rises (a b g : Nat) (ha : a < 2 ^ 16) (hb : b < 2 ^ 16) (hg : g < 2 ^ 16)
    (h : b % p = (a + 1 + g) % p) : a < b := by
  have := the_step_does_not_wrap a b g ha hb hg h
  omega

/-- Four live slots that each rise over the last are four different spends;
fewer live slots are a prefix of the same chain. -/
theorem rising_positions_are_different_spends (a b c d : Nat) (h1 : a < b) (h2 : b < c) (h3 : c < d) :
    a ≠ b ∧ a ≠ c ∧ a ≠ d ∧ b ≠ c ∧ b ≠ d ∧ c ≠ d := by
  omega

/-- A repeated spend needs a gap of `p - 1`, which the 16-bit range refuses. -/
theorem a_repeat_needs_a_wrapped_gap (a : Nat) :
    (a + 1 + (p - 1)) % p = a % p := by
  have : a + 1 + (p - 1) = a + p := by unfold p; omega
  rw [this, Nat.add_mod_right]

theorem positions_fit_sixteen_bits : 2 ^ depth = 2 ^ gapBits := rfl

theorem the_count's_columns_tile_its_width :
    colLive + slots = colPos ∧ colPos + slots = colGap ∧ colGap + (slots - 1) = colK ∧
    colK + 1 = colWalked ∧ colWalked + slots * 4 = colRoot ∧ colRoot + 4 = countWidth :=
  ⟨rfl, rfl, rfl, rfl, rfl, rfl⟩

/-! ## The tag and the statement -/

/-- The tag chain's row 0 under the wires: `nk` in lanes 1 to 4 and the week
in lane 5, the domain and two zeros pinned. -/
def tagRow0 (nk0 nk1 nk2 nk3 e : Nat) : List Nat := [activityDomain, nk0, nk1, nk2, nk3, e, 0, 0]

theorem the_tag_row_is_the_tag's_preimage (nk0 nk1 nk2 nk3 e : Nat) :
    (tagRow0 nk0 nk1 nk2 nk3 e).take 4 = [activityDomain, nk0, nk1, nk2] ∧
    (tagRow0 nk0 nk1 nk2 nk3 e).drop 4 = [nk3, e, 0, 0] := ⟨rfl, rfl⟩

/-- The key chain's row 0 under the wires: the same `nk` lanes as the tag's,
its own domain, and zero where the tag has the week. -/
def keyRow0 (nk0 nk1 nk2 nk3 : Nat) : List Nat := [keyDomain, nk0, nk1, nk2, nk3, 0, 0, 0]

theorem the_key_row_is_k's_preimage (nk0 nk1 nk2 nk3 : Nat) :
    (keyRow0 nk0 nk1 nk2 nk3).take 4 = [keyDomain, nk0, nk1, nk2] ∧
    (keyRow0 nk0 nk1 nk2 nk3).drop 4 = [nk3, 0, 0, 0] := ⟨rfl, rfl⟩

/-- K and T never share a preimage: their domains differ in lane 0. -/
theorem the_key_and_the_tag_differ_in_their_domain : keyDomain ≠ activityDomain := by decide

/-- The key's domain is the bytes "NOXACTK1". -/
theorem the_key_domain_is_noxactk1 :
    keyDomain = ((((((0x4E * 256 + 0x4F) * 256 + 0x58) * 256 + 0x41) * 256 + 0x43) * 256 + 0x54) * 256 + 0x4B) * 256 + 0x31 := rfl

/-- The tag's domain is the bytes "NOXACTV1". -/
theorem the_domain_is_noxactv1 :
    activityDomain = ((((((0x4E * 256 + 0x4F) * 256 + 0x58) * 256 + 0x41) * 256 + 0x43) * 256 + 0x54) * 256 + 0x56) * 256 + 0x31 := rfl

theorem the_ranges_cover_the_words :
    lambda + 4 = week ∧ week + 1 = count ∧ count + 1 = tag ∧ tag + 4 = payout ∧ payout + 4 = key ∧
    key + 4 = words :=
  ⟨rfl, rfl, rfl, rfl, rfl, rfl⟩

theorem a_chain_is_its_compressions_and_one_more : (compressions + 1) * rounds = 608 := rfl

theorem the_trace_is_two_to_the_thirteen :
    regionRows.foldl (· + ·) 0 ≤ 2 ^ logTrace ∧ 2 ^ (logTrace - 1) < regionRows.foldl (· + ·) 0 := by
  decide

end Shield.Activity
