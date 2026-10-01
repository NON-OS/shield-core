----------------------------- MODULE Notes -----------------------------
(*
 * Shielded notes as TLC checks them: two devices restored from one phrase,
 * each proving spends, relayers that settle a hand-off, lose it or are never
 * given it, the chain's nullifier set, syncs, and the owner taking back a
 * note whose hand-off will never be settled.
 *)
EXTENDS Naturals, FiniteSets

CONSTANTS Devices, NoteIds, MaxProofs

VARIABLES
    store,     \* per device, per note: "unspent", "pending" or "spent"
    handoffs,  \* proofs handed to a relayer and not yet settled or lost
    spent,     \* the chain's nullifier set
    proofs,    \* how many proofs each device made of each note
    settled    \* how many times the chain paid out each note

vars == <<store, handoffs, spent, proofs, settled>>

Init ==
    /\ store = [d \in Devices |-> [n \in NoteIds |-> "unspent"]]
    /\ handoffs = {}
    /\ spent = {}
    /\ proofs = [d \in Devices |-> [n \in NoteIds |-> 0]]
    /\ settled = [n \in NoteIds |-> 0]

\* A device proves a spend of a note it holds unspent, and marks it pending.
Prove(d, n) ==
    /\ store[d][n] = "unspent"
    /\ proofs[d][n] < MaxProofs
    /\ store' = [store EXCEPT ![d][n] = "pending"]
    /\ proofs' = [proofs EXCEPT ![d][n] = @ + 1]
    /\ handoffs' = handoffs \cup {<<d, n, proofs[d][n]>>}
    /\ UNCHANGED <<spent, settled>>

\* The pool accepts a nullifier once; a second proof of the note is refused.
Settle(h) ==
    /\ handoffs' = handoffs \ {h}
    /\ IF h[2] \in spent
          THEN UNCHANGED <<spent, settled>>
          ELSE /\ spent' = spent \cup {h[2]}
               /\ settled' = [settled EXCEPT ![h[2]] = @ + 1]
    /\ UNCHANGED <<store, proofs>>

Lose(h) == /\ handoffs' = handoffs \ {h} /\ UNCHANGED <<store, spent, proofs, settled>>

\* A sync marks every note whose nullifier is published as spent.
Sync(d) ==
    /\ store' = [store EXCEPT ![d] = [n \in NoteIds |->
                    IF n \in spent THEN "spent" ELSE store[d][n]]]
    /\ UNCHANGED <<handoffs, spent, proofs, settled>>

(*
 * The owner takes back a pending note. Allowed only after a sync that
 * found it unspent on chain; if an old hand-off settles later, the pool
 * refuses whichever proof comes second, so nothing is spent twice.
 *)
Release(d, n) ==
    /\ store[d][n] = "pending" /\ n \notin spent
    /\ store' = [store EXCEPT ![d][n] = "unspent"]
    /\ UNCHANGED <<handoffs, spent, proofs, settled>>

Next ==
    \/ \E d \in Devices, n \in NoteIds : Prove(d, n) \/ Release(d, n)
    \/ \E d \in Devices : Sync(d)
    \/ \E h \in handoffs : Settle(h) \/ Lose(h)

Spec == Init /\ [][Next]_vars /\ WF_vars(\E d \in Devices : Sync(d))
            /\ \A d \in Devices, n \in NoteIds : WF_vars(Release(d, n))

(* The core as it is today: no Release, so a lost hand-off freezes a note. *)
Today == Init /\ [][Next /\ ~\E d \in Devices, n \in NoteIds : Release(d, n)]_vars
            /\ WF_vars(\E d \in Devices : Sync(d))

(* Two devices, stale hand-offs and take-backs never pay a note out twice. *)
PaidOutAtMostOnce == \A n \in NoteIds : settled[n] <= 1

(* A device never shows a note as spendable once it has seen it spent. *)
SpentStaysSpent == \A d \in Devices, n \in NoteIds :
    store[d][n] = "spent" => n \in spent

(* A pending note is never proved again by the same device. *)
PendingIsNotSpendable == \A d \in Devices, n \in NoteIds :
    store[d][n] = "pending" => ~ENABLED Prove(d, n)

(* Every pending note is eventually settled or taken back: no money is
   frozen in this wallet by a hand-off nobody settles. *)
NothingFrozen == \A d \in Devices, n \in NoteIds :
    store[d][n] = "pending" ~> store[d][n] # "pending"
=============================================================================
