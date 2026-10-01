/-
  The wallet's machine checked part.

  What is proven here is what the wallet is trusted to get right in ordinary
  arithmetic and bookkeeping: that value is conserved, that a spent note stops
  being spendable, that a blinding seed cannot be used twice, that the amount
  codec round trips, and that the discovery filter never drops a note that is
  ours. The soundness of the STARK itself is proven elsewhere, in the prover's
  own Lean development, and is assumed here.
-/
import Shield.Amount
import Shield.Conserve
import Shield.Seed
import Shield.Store
import Shield.StoreProofs
import Shield.WipeProofs
import Shield.Filter
