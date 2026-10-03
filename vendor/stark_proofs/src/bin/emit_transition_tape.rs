// NONOS Operating System (AGPL-3.0-or-later)
//! The program-form outer's transition constraints as one straight-line
//! program over Fp2, for a verifier that evaluates them at z.
//!
//! The outer's transitions are written once over `Felt`, so running them on a
//! recording value writes down every operation they perform. The tape is the
//! constraint formulas themselves, flattened: a port generated from it has
//! nothing to transcribe by hand.
//!
//! Inputs, in order: the frame at z and g z (window times width values), the
//! periodic columns at z, and the two drawn challenges beta and gamma. Every
//! value is an Fp2, written [c0, c1]. Operations:
//!
//!     ["c", c0, c1]    a constant of the circuit
//!     ["i", k]         input k
//!     ["+", a, b]      ["-", a, b]      ["*", a, b]      over earlier results
//!     ["/", a]         the inverse of result a
//!
//! `outputs` lists the result that is transition i, in coefficient order.
//! Nothing is written unless replaying the tape on each oracle's frame,
//! periodic values and challenges reproduces that oracle's C_i(z), every one.
//!
//!     emit_transition_tape <out.json> <oracle.json> [<oracle.json> ...]
//!     emit_transition_tape <out.json> direct=<proof.publics.json> <oracle.json> [...]
//!     emit_transition_tape <out.json> attest=<proof.publics.json> <oracle.json> [...]
//!     emit_transition_tape <out.json> activity=<proof.publics.json> <oracle.json> [...]
//!
//! With `direct=` the circuit is the join-split proved for the chain with no
//! outer, rebuilt from those words, and its challenges are beta's and gamma's
//! `Fp2` components, four inputs.

use stark_proofs::crypto::stark::air::{Air, GenericTransition};
use stark_proofs::crypto::stark::field::{Fp, Fp2};
use stark_proofs::host::{die, read_text, Json};
use stark_proofs::shield::join::join_split_shape;
use stark_proofs::shield::member::TREE_DEPTH;
use stark_proofs::recursion_assembly::anchors::Anchors;
use stark_proofs::recursion_assembly::inner::{hasher, shield_join_split};
use stark_proofs::recursion_assembly::point::Point;
use stark_proofs::recursion_assembly::{assemble_over_gen_form, ComposeForm, Tamper};
use stark_proofs::wrap::{Op, Rec};
use std::fmt::Write as _;

/// The numbers in `text` after `"key":` up to the matching bracket, flat.
fn numbers(text: &str, key: &str) -> Vec<u64> {
    let at = text.find(&format!("\"{key}\"")).unwrap_or_else(|| die(&format!("no {key}")));
    let rest = &text[at..];
    let open = rest.find('[').unwrap_or_else(|| die(&format!("{key} is not a list")));
    let mut depth = 0usize;
    let mut end = open;
    for (i, ch) in rest[open..].char_indices() {
        match ch {
            '[' => depth += 1,
            ']' => {
                depth -= 1;
                if depth == 0 {
                    end = open + i;
                    break;
                }
            }
            _ => {}
        }
    }
    rest[open..=end]
        .split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty())
        .map(|s| s.parse().unwrap_or_else(|_| die("a number that does not parse")))
        .collect()
}

type Record = Box<dyn Fn(&[Rec<Fp2>], &[Rec<Fp2>], &[Rec<Fp2>]) -> Vec<Rec<Fp2>>>;

/// The circuit whose transitions are recorded: its frame width, periodic
/// count and transition count, how many challenge inputs it reads, and the
/// transition itself over the recording value.
struct Circuit {
    shape: (usize, usize, usize),
    n_chal: usize,
    record: Record,
}

impl Circuit {
    fn of<A: Air + GenericTransition + 'static>(air: A, n_chal: usize) -> Circuit {
        let shape = (
            Air::window_size(&air) * Air::trace_width(&air),
            Air::periodic_columns(&air).len(),
            Air::num_transition(&air),
        );
        Circuit {
            shape,
            n_chal,
            record: Box::new(move |w, p, c| air.transition_gen_at::<Rec<Fp2>>(w, p, c)),
        }
    }
}

fn pairs(v: &[u64]) -> Vec<Fp2> {
    v.chunks(2).map(|c| Fp2::new(Fp::from_u64(c[0]), Fp::from_u64(c[1]))).collect()
}

/// Each transition's C_i(z) as the oracle states it: the first pair of every
/// transition entry, which is its "c".
fn oracle_cs(text: &str, n: usize) -> Vec<Fp2> {
    let at = text.find("\"transitions\"").unwrap_or_else(|| die("no transitions"));
    text[at..]
        .split("\"c\": [")
        .skip(1)
        .take(n)
        .map(|s| {
            let body = &s[..s.find(']').unwrap_or_else(|| die("an unclosed c"))];
            let v: Vec<u64> = body.split(',').map(|x| x.trim().parse().unwrap_or_else(|_| die("bad c"))).collect();
            Fp2::new(Fp::from_u64(v[0]), Fp::from_u64(v[1]))
        })
        .collect()
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    if a.len() < 2 {
        die("usage: emit_transition_tape <out.json> <oracle.json> [<oracle.json> ...]");
    }
    let direct = a.iter().find_map(|s| s.strip_prefix("direct="));
    let attest = a.iter().find_map(|s| s.strip_prefix("attest="));
    let activity = a.iter().find_map(|s| s.strip_prefix("activity="));
    let oracles: Vec<&String> = a[1..]
        .iter()
        .filter(|s| !s.starts_with("direct=") && !s.starts_with("attest=") && !s.starts_with("activity="))
        .collect();
    if oracles.is_empty() {
        die("no oracle");
    }
    let h = hasher();
    // The drawn pair is an input, so the tape reads beta and gamma rather
    // than baking them: two in `Fp`, or four components in `Fp2`.
    let recorded = match (attest.or(activity), direct) {
        (Some(p), _) if activity.is_some() => {
            let words: Vec<Fp> = Json(&read_text(p)).u64s("publics").into_iter().map(Fp::from_u64).collect();
            let shape = stark_proofs::activity::shape(&words)
                .unwrap_or_else(|| die("the publics are not an activity statement's fourteen words"));
            Circuit::of(shape, 4)
        }
        (Some(p), _) => {
            let words: Vec<Fp> = Json(&read_text(p)).u64s("publics").into_iter().map(Fp::from_u64).collect();
            let shape = stark_proofs::attest::shape(&words)
                .unwrap_or_else(|| die("the publics are not an attestation statement's nine words"));
            Circuit::of(shape, 4)
        }
        (None, None) => Circuit::of(
            assemble_over_gen_form(
                &h,
                shield_join_split(&h),
                Tamper::None,
                usize::MAX,
                Point::emit_wiring(),
                Anchors::Collapsed,
                ComposeForm::Program,
            )
            .gen,
            2,
        ),
        (None, Some(p)) => {
            let words: Vec<Fp> = Json(&read_text(p)).u64s("publics").into_iter().map(Fp::from_u64).collect();
            let js = join_split_shape(TREE_DEPTH, &words);
            let n_chal = if js.wired().ext_challenges() { 4 } else { 2 };
            Circuit::of(js, n_chal)
        }
    };
    let (w, n, nt) = recorded.shape;
    let n_chal = recorded.n_chal;

    /*
     * Recorded on the first oracle's values, so the constants the recorder
     * folds are the circuit's and every input is a real point. The tape is
     * then held to every oracle by replay, which is the check that it is a
     * function of its inputs and not of the point it was recorded at.
     */
    let first = read_text(oracles[0]);
    let frame = pairs(&numbers(&first, "frame"));
    let periodic = pairs(&numbers(&first, "periodic_z"));
    let chal: Vec<Fp2> = numbers(&first, "challenges").into_iter().map(|c| Fp2::from_base(Fp::from_u64(c))).collect();
    if frame.len() != w || periodic.len() != n || chal.len() != n_chal {
        die(&format!(
            "the oracle's shape is not this circuit's: frame {} of {w}, periodic {} of {n}, challenges {} of {n_chal}",
            frame.len(),
            periodic.len(),
            chal.len()
        ));
    }
    Rec::<Fp2>::start();
    let win_r: Vec<Rec<Fp2>> = (0..w).map(|i| Rec::input(i, frame[i])).collect();
    let per_r: Vec<Rec<Fp2>> = (0..n).map(|i| Rec::input(w + i, periodic[i])).collect();
    let chal_r: Vec<Rec<Fp2>> = (0..n_chal).map(|i| Rec::input(w + n + i, chal[i])).collect();
    let outs: Vec<Rec<Fp2>> = (recorded.record)(&win_r, &per_r, &chal_r);
    let tape = Rec::<Fp2>::take();
    if outs.len() != nt {
        die("the recorded transition count is not the circuit's");
    }

    for path in &oracles {
        let text = read_text(path);
        let fr = pairs(&numbers(&text, "frame"));
        let pz = pairs(&numbers(&text, "periodic_z"));
        let ch: Vec<Fp2> = numbers(&text, "challenges").into_iter().map(|c| Fp2::from_base(Fp::from_u64(c))).collect();
        let inputs: Vec<Fp2> = fr.iter().chain(&pz).chain(&ch).copied().collect();
        let replayed = tape.replay(&inputs);
        let got: Vec<Fp2> = outs.iter().map(|r| replayed[r.id() as usize]).collect();
        let want = oracle_cs(&text, nt);
        if got != want {
            let i = got.iter().zip(&want).position(|(g, w)| g != w).unwrap_or(0);
            die(&format!("{path}: the tape's transition {i} is not the oracle's; nothing written"));
        }
        println!("{path}: all {nt} transitions reproduced from the tape");
    }

    let mut ops = String::new();
    for (i, op) in tape.ops.iter().enumerate() {
        let sep = if i == 0 { "" } else { ",\n" };
        let _ = match *op {
            Op::Const => {
                let v = tape.vals[i];
                write!(ops, "{sep}    [\"c\", {}, {}]", v.c0.to_u64(), v.c1.to_u64())
            }
            Op::Input(k) => write!(ops, "{sep}    [\"i\", {k}]"),
            Op::Add(x, y) => write!(ops, "{sep}    [\"+\", {x}, {y}]"),
            Op::Sub(x, y) => write!(ops, "{sep}    [\"-\", {x}, {y}]"),
            Op::Mul(x, y) => write!(ops, "{sep}    [\"*\", {x}, {y}]"),
            Op::Inv(x) => write!(ops, "{sep}    [\"/\", {x}]"),
        };
    }
    let (consts, inputs_n, adds, subs, muls, invs) = tape.counts();
    let outputs: Vec<String> = outs.iter().map(|r| r.id().to_string()).collect();
    let json = format!(
        "{{\n  \"form\": \"program\",\n  \"field\": \"Fp2 over Goldilocks, u^2 = 7\",\n  \
         \"inputs\": {{\"frame\": {w}, \"periodic\": {n}, \"challenges\": {n_chal}}},\n  \
         \"counts\": {{\"ops\": {}, \"consts\": {consts}, \"inputs\": {inputs_n}, \"add\": {adds}, \
         \"sub\": {subs}, \"mul\": {muls}, \"inv\": {invs}}},\n  \"outputs\": [{}],\n  \"ops\": [\n{ops}\n  ]\n}}\n",
        tape.len(),
        outputs.join(", ")
    );
    std::fs::write(&a[0], json).unwrap_or_else(|e| die(&format!("cannot write {}: {e}", a[0])));
    println!(
        "wrote {}: {} ops = {consts} constants + {inputs_n} inputs + {adds} adds + {subs} subs + {muls} muls + {invs} invs, {nt} outputs",
        a[0],
        tape.len()
    );
}
