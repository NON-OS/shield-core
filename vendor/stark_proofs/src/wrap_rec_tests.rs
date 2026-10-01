// NONOS Operating System (AGPL-3.0-or-later)

//! The outer's constraints at z, recorded as a program, replay to the same
//! values the outer computes, and the program's length is printed: it is
//! the row count of the region a narrow wrap enforces them in.

use crate::crypto::stark::air::{Air, AirExt, GenericTransition};
use crate::crypto::stark::field::{Fp, Fp2};
use crate::wrap::{Op, Rec};
use crate::wrap_gen_tests::typed_outer;

fn stream(seed: u64) -> impl FnMut() -> Fp2 {
    let mut x = seed;
    move || {
        x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let c0 = Fp::from_u64(x >> 1);
        x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        Fp2 { c0, c1: Fp::from_u64(x >> 1) }
    }
}

#[test]
fn the_recorded_program_replays_the_outers_transitions_at_z() {
    let asm = typed_outer(2);
    let air = &asm.gen;
    let w = Air::window_size(air) * Air::trace_width(air);
    let n = Air::periodic_columns(air).len();
    let mut next = stream(0x0ec0_4d3d);
    let window: Vec<Fp2> = (0..w).map(|_| next()).collect();
    let periodic: Vec<Fp2> = (0..n).map(|_| next()).collect();
    let chal: Vec<Fp2> = air.challenges_gen().iter().map(|c| Fp2::from_base(*c)).collect();
    let direct = AirExt::transition_ext(air, &window, &periodic);

    Rec::<Fp2>::start();
    let inputs: Vec<Fp2> = window.iter().chain(&periodic).chain(&chal).copied().collect();
    let win_r: Vec<Rec<Fp2>> = (0..w).map(|i| Rec::input(i, window[i])).collect();
    let per_r: Vec<Rec<Fp2>> = (0..n).map(|i| Rec::input(w + i, periodic[i])).collect();
    let chal_r: Vec<Rec<Fp2>> = (0..chal.len()).map(|i| Rec::input(w + n + i, chal[i])).collect();
    let outs: Vec<Rec<Fp2>> = air.transition_gen_at::<Rec<Fp2>>(&win_r, &per_r, &chal_r);
    let tape = Rec::<Fp2>::take();

    let recorded: Vec<Fp2> = outs.iter().map(|r| tape.vals[r.id() as usize]).collect();
    assert_eq!(recorded, direct, "the recorded evaluation differs from the outer's own");

    let replayed = tape.replay(&inputs);
    let from_replay: Vec<Fp2> = outs.iter().map(|r| replayed[r.id() as usize]).collect();
    assert_eq!(from_replay, direct, "the program replayed from the tape differs from the outer's own");

    let mut other = stream(0x5eed);
    let window2: Vec<Fp2> = (0..w).map(|_| other()).collect();
    let periodic2: Vec<Fp2> = (0..n).map(|_| other()).collect();
    let inputs2: Vec<Fp2> = window2.iter().chain(&periodic2).chain(&chal).copied().collect();
    let replayed2 = tape.replay(&inputs2);
    let from_replay2: Vec<Fp2> = outs.iter().map(|r| replayed2[r.id() as usize]).collect();
    let direct2 = AirExt::transition_ext(air, &window2, &periodic2);
    assert_eq!(from_replay2, direct2, "the program is not a function of its inputs");

    let (consts, inputs_n, adds, subs, muls, invs) = tape.counts();
    let assert_zero = outs.len();
    println!(
        "outer transitions at z as a program: {} ops = {consts} constants + {inputs_n} inputs + {adds} adds + {subs} subs + {muls} muls + {invs} invs; {assert_zero} outputs; inputs {} = {w} window + {n} periodic + {} challenges",
        tape.len(),
        inputs.len(),
        chal.len()
    );
    assert!(tape.ops.iter().any(|o| matches!(o, Op::Mul(..))), "a program with no multiplication is not this circuit");
}
