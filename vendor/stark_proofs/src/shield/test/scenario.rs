// NONOS Operating System (AGPL-3.0-or-later)

use super::fixture::{owned, plain, secret};
use crate::shield::batch::assemble;
use crate::shield::join::address_from_u64;
#[cfg(test)]
use crate::shield::join::address_limbs;
use crate::shield::join::{intent_parts, IntentParts, JoinSplit, Settle, Spend};
use crate::shield::key::Break;
use crate::shield::note::Note;

/// 1000 + 2000 spent, 1500 + 1200 created, 200 out publicly, 100 in fees.
pub fn balanced_flip(brk: Break, flip: Option<usize>) -> JoinSplit {
    let sks = [secret(1), secret(2)];
    let ins = [owned(sks[0], 0, 1000), owned(sks[1], 10, 2000)];
    let outs = [plain(20, 1500), plain(30, 1200)];
    build(&ins, &outs, sks, 200, 100, brk, flip)
}

pub fn balanced(brk: Break) -> JoinSplit {
    balanced_flip(brk, None)
}

/// The same spend against the tree the pool deploys. `balanced` builds a minimal
/// instance, which is what a binding gate wants and is not what a transfer costs.
pub fn balanced_deployed(brk: Break) -> JoinSplit {
    balanced_at(super::depth::DEPLOYED, brk)
}

/// The deployed spend against a pool of a stated depth. The depth is a pool
/// constant, not a circuit one, so what it costs the circuit is a question with
/// an answer rather than a preference: `shield::test::depth_cost`.
pub fn balanced_at(depth: usize, brk: Break) -> JoinSplit {
    let mut b = assemble(alloc::vec![balanced_parts_at(depth, brk)]);
    JoinSplit {
        wired: b.wired,
        witness: b.witness,
        intent: b.intents.remove(0),
    }
}

/// The same spend one step earlier, before the assembly stacks it.
///
/// A gate that wants the bindings the circuit carries has to assemble them
/// itself, because `JoinSplit` keeps the wired circuit and drops the class list
/// that produced it. `balanced_at` is this plus the assembly, so the two cannot
/// describe different spends.
pub fn balanced_parts_at(depth: usize, brk: Break) -> IntentParts {
    let sks = [secret(1), secret(2)];
    let ins = [owned(sks[0], 0, 1000), owned(sks[1], 10, 2000)];
    let outs = [plain(20, 1500), plain(30, 1200)];
    let st = Settle {
        not_before: 0,
        clearing_price: 1_000_000,
        recipient: address_from_u64(0xBEEF),
        fee_recipient: [0; 20],
    };
    intent_parts(
        [
            Spend {
                note: &ins[0],
                sk: sks[0],
            },
            Spend {
                note: &ins[1],
                sk: sks[1],
            },
        ],
        [&outs[0], &outs[1]],
        200,
        100,
        brk,
        st,
        None,
        depth,
    )
}

pub fn build(
    ins: &[Note; 2],
    outs: &[Note; 2],
    sks: [[crate::crypto::stark::field::Fp; crate::crypto::stark::air::RATE]; 2],
    public_amount: u64,
    fee: u64,
    brk: Break,
    flip: Option<usize>,
) -> JoinSplit {
    let st = Settle {
        not_before: 0,
        clearing_price: 1_000_000,
        recipient: address_from_u64(0xBEEF),
        fee_recipient: [0; 20],
    };
    crate::shield::join::join_split_at(
        super::depth::MINIMAL,
        [
            Spend {
                note: &ins[0],
                sk: sks[0],
            },
            Spend {
                note: &ins[1],
                sk: sks[1],
            },
        ],
        [&outs[0], &outs[1]],
        public_amount,
        fee,
        brk,
        st,
        flip,
    )
}

/// The intent words at a clearing price, for the batch price gate. Test only:
/// the scenarios around it are built by the recursion as well, this one is not.
#[cfg(test)]
pub(super) fn intent_at_price(price: u64) -> alloc::vec::Vec<crate::crypto::stark::field::Fp> {
    use crate::crypto::stark::air::RATE;
    use crate::crypto::stark::field::Fp;
    use crate::shield::join::publics::Intent;
    Intent {
        not_before: 0,
        input_sums: [0, 0],
        note_root: [Fp::from_u64(1); RATE],
        assoc_root: [Fp::from_u64(2); RATE],
        nf: [[Fp::from_u64(3); RATE], [Fp::from_u64(4); RATE]],
        out_cm: [[Fp::from_u64(5); RATE], [Fp::from_u64(6); RATE]],
        public_amount: 200,
        fee: 100,
        asset_id: 0,
        clearing_price: price,
        recipient: address_limbs(&address_from_u64(0xBEEF)),
        fee_recipient: address_limbs(&address_from_u64(0xFEE)),
    }
    .words()
}
