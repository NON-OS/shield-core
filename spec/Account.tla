---------------------------- MODULE Account ----------------------------
(*
 * The public account's sends, as TLC checks them: reviews, the owner's yes,
 * locking and restoring another wallet between the two, relays that lag,
 * mine or drop, and the nonce floor this device keeps.
 *
 * The floor is not a timer. The device keeps the hash of each send and asks
 * the send relays which are still held; the floor is one past the highest of
 * those. A read RPC may not see a private relay's pool at all, which the
 * lagging count below allows. Time is ticks, and a review lives for Valid.
 *)
EXTENDS Naturals, FiniteSets

CONSTANTS Accounts, MaxNonce, Valid, Fresh, MaxAge

None == "none"
\* No review waiting: the id is zero, and no real review has id zero.
NoRev == [id |-> 0, from |-> CHOOSE a \in Accounts : TRUE, nonce |-> 0, age |-> 0]

VARIABLES
    session,   \* the unlocked account, or None
    review,    \* the send waiting for a yes, or None
    chain,     \* mined nonces per account
    pool,      \* broadcast and not yet mined or dropped
    floor,     \* the recorded next nonce per account, and its age
    sent,      \* every broadcast, with the key that signed it
    nextId

vars == <<session, review, chain, pool, floor, sent, nextId>>

Max(a, b) == IF a > b THEN a ELSE b
Waiting(a) == {t \in pool : t.from = a}

Init ==
    /\ session = None
    /\ review = NoRev
    /\ chain = [a \in Accounts |-> 0]
    /\ pool = {}
    /\ floor = [a \in Accounts |-> [next |-> 0, age |-> MaxAge]]
    /\ sent = {}
    /\ nextId = 1

\* Unlock, restore or lock: the core drops any review with the session.
Open(a) == /\ session' = a /\ review' = NoRev
           /\ UNCHANGED <<chain, pool, floor, sent, nextId>>
Lock == /\ session' = None /\ review' = NoRev
        /\ UNCHANGED <<chain, pool, floor, sent, nextId>>

(*
 * A review reads the RPC's pending count, which may lag behind this
 * device's own broadcasts, and takes the larger of it and a fresh floor.
 *)
Review ==
    /\ session # None /\ nextId <= MaxNonce + 2
    /\ \E seen \in chain[session] .. chain[session] + Cardinality(Waiting(session)) :
        LET held == {t.nonce + 1 : t \in Waiting(session)}
            f == IF held = {} THEN 0 ELSE CHOOSE m \in held : \A k \in held : k <= m
            n == Max(seen, f)
        IN /\ n <= MaxNonce
           /\ review' = [id |-> nextId, from |-> session, nonce |-> n, age |-> 0]
    /\ nextId' = nextId + 1
    /\ UNCHANGED <<session, chain, pool, floor, sent>>

\* The core signs only a live review, for the account that made it.
Confirm ==
    /\ review.id # 0 /\ session # None
    /\ review.age < Valid
    /\ session = review.from
    /\ LET t == [id |-> review.id, from |-> review.from, nonce |-> review.nonce]
       IN /\ pool' = pool \cup {t}
          /\ sent' = sent \cup {[id |-> t.id, from |-> t.from, signer |-> session]}
          /\ floor' = [floor EXCEPT ![review.from] =
                 [next |-> Max(review.nonce + 1,
                               IF @.age < Fresh THEN @.next ELSE 0), age |-> 0]]
    /\ review' = NoRev
    /\ UNCHANGED <<session, chain, nextId>>

\* A transaction is mined when its nonce is next; one below is stale.
Mine(t) ==
    /\ t.nonce = chain[t.from]
    /\ chain' = [chain EXCEPT ![t.from] = @ + 1]
    /\ pool' = {u \in pool : ~(u.from = t.from /\ u.nonce <= t.nonce)}
    /\ UNCHANGED <<session, review, floor, sent, nextId>>

\* A private relay can drop what it never mined.
Drop(t) == /\ pool' = pool \ {t}
           /\ UNCHANGED <<session, review, chain, floor, sent, nextId>>

Tick ==
    /\ floor' = [a \in Accounts |-> [floor[a] EXCEPT !.age = IF @ < MaxAge THEN @ + 1 ELSE @]]
    /\ review' = IF review.id = 0 \/ review.age >= Valid THEN review
                 ELSE [review EXCEPT !.age = @ + 1]
    /\ UNCHANGED <<session, chain, pool, sent, nextId>>

Next ==
    \/ \E a \in Accounts : Open(a)
    \/ Lock \/ Review \/ Confirm \/ Tick
    \/ \E t \in pool : Mine(t) \/ Drop(t)

Spec == Init /\ [][Next]_vars

(* Every broadcast is signed by the key of the account it was reviewed for. *)
SignedByItsOwnAccount == \A t \in sent : t.signer = t.from

(* This device never has two sends waiting on one nonce, however long the
   first one waits and whatever the read RPC can see. *)
NoNonceTwice ==
    \A t, u \in pool : (t.from = u.from /\ t.nonce = u.nonce) => t = u

(* When nothing of this account waits and the RPC sees the chain as it is,
   a review uses the chain's own next nonce: a send a relay dropped never
   leaves the account stuck behind a nonce that will not be used. *)
NeverStuck ==
    [][(Review /\ Waiting(session) = {}) => review'.nonce = chain[session]]_vars

TypeOK == session \in Accounts \cup {None} /\ nextId \in Nat
=============================================================================
