// NONOS Operating System (AGPL-3.0-or-later)
//! Whether the program-form outer's periodic columns depend on the inner proof.
//!
//!     diff_program_periodic <in.inner> <in.inner.intent.json>
//!
//! The one-transaction verifier bakes one periodic root. `diff_periodic`
//! settled that the strip-form outer's periodic set depends only on the
//! inner's shape; this asks the same of the program form. It assembles the
//! program-form outer over the release fixture's inner and over a relayed
//! inner, and reports every periodic column that differs, with its first
//! differing row. None means one verifier serves every spend; any means the
//! deployed root belongs to one inner proof.

use stark_proofs::crypto::stark::air::{periodic_root_poseidon, Air};
use stark_proofs::crypto::stark::field::Fp;
use stark_proofs::host::{die, read_text, Json};
use stark_proofs::proof_wire::deserialize_p_rounds;
use stark_proofs::recursion_assembly::anchors::Anchors;
use stark_proofs::recursion_assembly::inner::{self, pack_air, shield_join_split, GRIND};
use stark_proofs::recursion_assembly::point::Point;
use stark_proofs::recursion_assembly::{assemble_over_gen_form, ComposeForm, Tamper};
use stark_proofs::shield::join::join_split_shape;
use stark_proofs::shield::member::TREE_DEPTH;

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let (inner_path, intent_path) = match (a.first(), a.get(1)) {
        (Some(i), Some(t)) => (i.clone(), t.clone()),
        _ => die("usage: diff_program_periodic <in.inner> <in.inner.intent.json>"),
    };
    let h = inner::hasher();
    let program = |inn| {
        assemble_over_gen_form(
            &h,
            inn,
            Tamper::None,
            usize::MAX,
            Point::emit_wiring(),
            Anchors::Collapsed,
            ComposeForm::Program,
        )
        .gen
        .into_wired()
    };
    let fixture = program(shield_join_split(&h));

    let intent: Vec<Fp> =
        Json(&read_text(&intent_path)).u64s("publics").into_iter().map(Fp::from_u64).collect();
    let bytes = std::fs::read(&inner_path).unwrap_or_else(|e| die(&format!("{inner_path}: {e}")));
    let proof = deserialize_p_rounds(&bytes).unwrap_or_else(|| die("not a two round inner proof"));
    let shape = join_split_shape(TREE_DEPTH, &intent);
    let root = periodic_root_poseidon(&shape, inner::extra(), &h);
    let relayed = program(pack_air(&h, shape, proof, intent, root, inner::extra(), GRIND));

    let (pa, pb) = (fixture.periodic_columns(), relayed.periodic_columns());
    println!("widths {} {}, periodic columns {} {}", Air::trace_width(&fixture), Air::trace_width(&relayed), pa.len(), pb.len());
    let mut differ = 0;
    for (c, (x, y)) in pa.iter().zip(pb.iter()).enumerate() {
        if let Some(r) = x.iter().zip(y.iter()).position(|(u, v)| u != v) {
            differ += 1;
            if differ <= 20 {
                println!("column {c} differs first at row {r}: {} vs {}", x[r].to_u64(), y[r].to_u64());
            }
        }
    }
    println!("{differ} of {} periodic columns differ", pa.len().min(pb.len()));
}
