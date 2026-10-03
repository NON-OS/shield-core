-- NONOS Operating System (AGPL-3.0-or-later)
import Shield.Intent

/-!
The attestation statement (`stark_proofs/src/attest`): one slot of a 256-slot
policy or boot tree, a kernel's, a capsule's or a bootloader's.

Nine public words: the root (words 0 to 3), the context digest's four words
(4 to 7), the kind (8). Each is wired to one cell of the slot's chain:

- the root to lanes 0 to 3 of the checkpoint's row, where the walk ends;
- the digest to lanes 1 to 4 of row 0 and the kind to lane 5, which is the
  leaf's preimage `[NONOSLV3, d0, d1, d2 | d3, kind, 0, 0]`.

Row 0's other lanes are constant pins: the leaf domain in lane 0, zero in
lanes 6 and 7. What is proved:

- the wires reach nine different cells, and none is a pinned one, so no word is
  tied to a constant and no two words to one cell;
- row 0 under the wires is exactly the kernel's v3 leaf preimage;
- the root's cells are the checkpoint row's first four lanes, inside the chain;
- the three regions fit 2^14 rows and overflow 2^13, so the trace is 2^14;
- the provable kinds are 0, 1 and 3, never the padding kind 2;
- the statement's three ranges cover words 0 to 8 without overlap.

`stark_proofs/src/attest/test.rs` reads the constants and the wire table out
of this file and holds them equal to the circuit's.
-/

namespace Shield.Attest

def depth : Nat := 8
def rounds : Nat := 32
def words : Nat := 9
def root : Nat := 0
def digest : Nat := 4
def kind : Nat := 8
def leafDomain : Nat := 5642814960725415475
def padKind : Nat := 2
def logTrace : Nat := 14

/-- The row of the chain where the walked root sits. -/
def checkpointRow : Nat := (1 + depth) * rounds

/-- The chain's rows, the statement's, the padding's. -/
def chainRows : Nat := (2 + depth) * rounds
def publicsRows : Nat := 16
def padRows : Nat := 8192

/-- `(word, row, lane)`: the wire table, as the circuit builds it. -/
def wires : List (Nat × Nat × Nat) :=
  [(0, 288, 0), (1, 288, 1), (2, 288, 2), (3, 288, 3),
   (4, 0, 1), (5, 0, 2), (6, 0, 3), (7, 0, 4),
   (8, 0, 5)]

/-- `(row, lane)`: the constant pins. -/
def pins : List (Nat × Nat) := [(0, 0), (0, 6), (0, 7)]

def cells (l : List (Nat × Nat × Nat)) : List (Nat × Nat) := l.map fun w => (w.2.1, w.2.2)

def distinct : List (Nat × Nat) → Bool
  | [] => true
  | x :: xs => !xs.contains x && distinct xs

theorem the_checkpoint_row_is_288 : checkpointRow = 288 := rfl

theorem the_table_wires_every_word_once : wires.map (·.1) = List.range words := rfl

theorem the_wires_reach_nine_cells : distinct (cells wires) = true := rfl

theorem no_wire_meets_a_pin : (cells wires).all (fun c => !pins.contains c) = true := rfl

/-- The root's four words sit in the checkpoint row's lanes 0 to 3, in order. -/
theorem the_root_is_the_walk's_end :
    (wires.take 4).map (fun w => w.2) = [(checkpointRow, 0), (checkpointRow, 1), (checkpointRow, 2), (checkpointRow, 3)] :=
  rfl

/-- Row 0 under the wires and the pins is the kernel's v3 leaf preimage. -/
def row0 (d0 d1 d2 d3 k : Nat) : List Nat := [leafDomain, d0, d1, d2, d3, k, 0, 0]

theorem row0_is_the_leaf_preimage (d0 d1 d2 d3 k : Nat) :
    (row0 d0 d1 d2 d3 k).take 4 = [leafDomain, d0, d1, d2] ∧
    (row0 d0 d1 d2 d3 k).drop 4 = [d3, k, 0, 0] := ⟨rfl, rfl⟩

/-- The digest's words go to lanes 1 to 4 of row 0 and the kind to lane 5:
the lanes `row0` puts them in. -/
theorem the_leaf_lanes_are_the_wired_ones :
    (wires.drop 4).map (fun w => w.2) = [(0, 1), (0, 2), (0, 3), (0, 4), (0, 5)] := rfl

theorem the_checkpoint_is_inside_the_chain : checkpointRow < chainRows := by decide

theorem the_trace_is_two_to_the_fourteen :
    chainRows + publicsRows + padRows ≤ 2 ^ logTrace ∧
    2 ^ (logTrace - 1) < chainRows + publicsRows + padRows := by decide

def provable (k : Nat) : Bool := k == 0 || k == 1 || k == 3

theorem padding_is_never_provable : provable padKind = false := rfl

theorem the_three_kinds_are_provable :
    provable 0 = true ∧ provable 1 = true ∧ provable 3 = true := ⟨rfl, rfl, rfl⟩

theorem the_ranges_cover_the_words :
    root + 4 = digest ∧ digest + 4 = kind ∧ kind + 1 = words := ⟨rfl, rfl, rfl⟩

theorem a_tree_of_this_depth_has_256_slots : 2 ^ depth = 256 := rfl

end Shield.Attest
