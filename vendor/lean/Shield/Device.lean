-- NONOS Operating System (AGPL-3.0-or-later)

/-!
The anonymous device statement (`nonos-device-attest`), as shipped: four
Poseidon chains and a padding region in one 2^14-row trace, and one wire.

| kind | chain | compressions | rows | row 0, pinned lanes | at the checkpoint |
|---|---|---|---|---|---|
| 0 | bootloader in B | 9 | 320 | 0 domain, 5 kind 3, 6 and 7 zero | B |
| 1 | kernel in P | 9 | 320 | 0 domain, 5 kind 0, 6 and 7 zero | P |
| 2 | device in R | 21 | 704 | 0 device domain, 5 to 7 zero | R |
| 3 | tag | 1 | 64 | 0 tag domain, 5 and 6 the scope, 7 zero | the tag |
| 4 | padding | none | 8192 | nothing | nothing |

The only binding between regions: lanes 1 to 4 of row 0 in the device chain
equal the same lanes in the tag chain. That is the secret, so the tag is the
enrolled device's and no other secret's.

What is proved here, over the layout the circuit's `kind_map` reports:

- each chain's rows are (compressions + 1) * 32, and the regions stack to 9,600
  rows, inside 2^14 and past 2^13, so the trace is 2^14;
- each chain's checkpoint row is inside its region;
- each chain pins eight cells, four at row 0 and four at the checkpoint, 32 in
  all; no pinned lane of row 0 is one of the wired lanes 1 to 4;
- the wire joins four distinct cells of the device chain to four distinct cells
  of the tag chain, lane for lane, and no other region is wired;
- the kinds' periodic columns start 11 apart, at 5, 16, 27 and 38, and the
  padding's at 49 with no slots;
- the bootloader's kind 3 and the kernel's kind 0 differ, and neither is the
  padding kind 2.

`nonos-device-attest`'s `the_shipped_shape_is_the_one_the_lean_model_describes`
reads these constants out of this file and holds `build(statement(20))` to them.
-/

namespace Shield.Device

def rounds : Nat := 32
def logTrace : Nat := 14
def width : Nat := 33
def registryDepth : Nat := 20
def bootDepth : Nat := 8
def kernelDepth : Nat := 8

/-- Compressions per chain: the leaf's, then one per level. The tag is one. -/
def compressions : List Nat := [1 + bootDepth, 1 + kernelDepth, 1 + registryDepth, 1]

def chainRows : List Nat := compressions.map fun c => (c + 1) * rounds
def padRows : Nat := 8192

/-- Each region's first row in the stacked trace. -/
def offsets : List Nat := [0, 320, 640, 1344, 1408]

/-- The checkpoint row inside each chain, where its root or tag is pinned. -/
def checkpoints : List Nat := compressions.map fun c => c * rounds

/-- `(first_periodic, slots, num_transition, instances, width)` per kind. -/
def kindMap : List (Nat × Nat × Nat × Nat × Nat) :=
  [(5, 11, 30, 1, 29), (16, 11, 30, 1, 29), (27, 11, 30, 1, 29), (38, 11, 30, 1, 29), (49, 0, 0, 1, 1)]

/-- Row 0's pinned lanes, per chain. -/
def pinnedLanes : List Nat := [0, 5, 6, 7]
def wiredLanes : List Nat := [1, 2, 3, 4]
def kindBootloader : Nat := 3
def kindKernel : Nat := 0
def kindPad : Nat := 2

/-- The wire, as `(row, lane)` pairs in the stacked trace. -/
def wire : List ((Nat × Nat) × (Nat × Nat)) :=
  wiredLanes.map fun l => ((640, l), (1344, l))

def sum : List Nat → Nat
  | [] => 0
  | x :: xs => x + sum xs

def distinct : List (Nat × Nat) → Bool
  | [] => true
  | x :: xs => !xs.contains x && distinct xs

theorem the_chains_are_the_reported_rows : chainRows = [320, 320, 704, 64] := rfl

theorem the_offsets_are_the_running_sums :
    offsets = [0, 320, 320 + 320, 320 + 320 + 704, 320 + 320 + 704 + 64] := rfl

theorem the_trace_is_two_to_the_fourteen :
    sum chainRows + padRows = 9600 ∧
    sum chainRows + padRows ≤ 2 ^ logTrace ∧
    2 ^ (logTrace - 1) < sum chainRows + padRows := by decide

theorem every_checkpoint_is_inside_its_chain :
    (checkpoints.zip chainRows).all (fun p => p.1 < p.2) = true := rfl

theorem each_chain_pins_eight_cells : pinnedLanes.length + 4 = 8 ∧ 4 * 8 = 32 := ⟨rfl, rfl⟩

theorem no_pinned_lane_is_wired : pinnedLanes.all (fun l => !wiredLanes.contains l) = true := rfl

theorem the_wire_joins_device_to_tag_lane_for_lane :
    wire = [((640, 1), (1344, 1)), ((640, 2), (1344, 2)), ((640, 3), (1344, 3)), ((640, 4), (1344, 4))] := rfl

theorem the_wired_cells_are_distinct :
    distinct (wire.map (·.1) ++ wire.map (·.2)) = true := rfl

theorem the_wire_rows_are_the_device_and_tag_starts :
    offsets.get? 2 = some 640 ∧ offsets.get? 3 = some 1344 := ⟨rfl, rfl⟩

theorem the_periodic_columns_start_eleven_apart :
    kindMap.map (·.1) = [5, 16, 27, 38, 49] := rfl

theorem the_padding_has_no_slots_and_no_constraints :
    kindMap.get? 4 = some (49, 0, 0, 1, 1) := rfl

theorem the_kinds_keep_apart :
    kindBootloader ≠ kindKernel ∧ kindBootloader ≠ kindPad ∧ kindKernel ≠ kindPad := by decide

end Shield.Device
