// NONOS Operating System (AGPL-3.0-or-later)

//! The composition region in either of its forms: the wide row of slots with
//! its accumulator strip that the settlement outer ships, or the compose
//! gadget recorded as a straight-line program and enforced three columns
//! wide, which is the wrap's.

use super::inner::Inner;
use super::{compose_step, strip};
use crate::crypto::stark::air::{Air, AirExt, GenericTransition, LineEval, OuterRegion};
use crate::crypto::stark::field::Fp;
use crate::wrap::Rec;
use alloc::sync::Arc;
use alloc::vec::Vec;

/// How the composition over the inner is laid out. `Strip` is the wide row
/// of slots with its accumulator strip, the settlement outer's form; `Program`
/// is the compose gadget recorded as a straight-line program and enforced
/// three columns wide, the wrap's form.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ComposeForm {
    Strip,
    Program,
}

/// What the assembly needs of the composition region whichever form holds
/// it: where each named slot is and, in the program form, the evaluator row
/// of every base column and the operand cycles to wire.
pub(super) struct ComposeMeta {
    pub(super) frame_len: usize,
    pub(super) n_coeff: usize,
    pub(super) c_periodic_col: usize,
    pub(super) c_z_col: usize,
    pub(super) c_coeff_col: usize,
    pub(super) c_comp_z_col: usize,
    pub(super) n_chal: usize,
    pub(super) c_chal_col: usize,
    pub(super) flat_acc: Vec<usize>,
    pub(super) c_rows: Vec<usize>,
    pub(super) eval_cycles: Vec<((usize, usize), (usize, usize))>,
    /// Base column of public word 0 in the compose region, and how many; zero
    /// words on the strip form, which keeps its constants.
    pub(super) c_pub_col: usize,
    pub(super) n_pub: usize,
}

impl ComposeMeta {
    pub(super) fn of<A: AirExt + GenericTransition>(
        c: &crate::crypto::stark::air::ComposeCheckGen<A>,
        flat_acc: Vec<usize>,
    ) -> ComposeMeta {
        let n_chal = c.n_chal();
        ComposeMeta {
            frame_len: c.frame_len(),
            n_coeff: c.num_coeff(),
            c_periodic_col: c.periodic_col(0),
            c_z_col: c.z_col(),
            c_coeff_col: c.coeff_col(0),
            c_comp_z_col: c.comp_z_col(),
            n_chal,
            c_chal_col: if n_chal == 0 { 0 } else { c.chal_col(0) },
            flat_acc,
            c_rows: Vec::new(),
            eval_cycles: Vec::new(),
            c_pub_col: if c.n_public() == 0 { 0 } else { c.public_col(0) },
            n_pub: c.n_public(),
        }
    }
}

/// What the layout keeps of the strip: its cycles, accumulator columns,
/// final row, and shape.
pub(super) type StripRest =
    (Vec<((usize, usize), strip::Home)>, Vec<usize>, usize, usize, usize, usize, usize);

/// The composition regions and their traces, the strip's remains when there
/// is one, and what the layout needs to know about the slots.
pub(super) type ComposeRegions<A> = (Vec<OuterRegion<A>>, Vec<Vec<Fp>>, Option<StripRest>, ComposeMeta);

pub(super) fn compose_regions<A: AirExt + GenericTransition + 'static>(
    inner: Inner<A>,
    form: ComposeForm,
) -> ComposeRegions<A> {
    match form {
        ComposeForm::Strip => {
            std::eprintln!("[asm] strip side");
            let ss = strip::strip_side(&inner);
            std::eprintln!("[asm] compose gen");
            let (cregion, ctrace) =
                compose_step::compose_gen_region_strip(inner, ss.stmt.clone());
            std::eprintln!("[asm] compose done");
            let acc: Vec<usize> = (0..ss.acc_cols.len() / 2).map(|i| cregion.acc_col(i)).collect();
            let cm = ComposeMeta::of(&cregion, acc);
            let gens: Vec<OuterRegion<A>> = alloc::vec![
                OuterRegion::Compose(Arc::new(cregion)),
                OuterRegion::Strip(Arc::new(ss.region)),
            ];
            let traces: Vec<Vec<Fp>> = alloc::vec![ctrace, ss.trace];
            let rest: StripRest =
                (ss.cycles, ss.acc_cols, ss.final_row, ss.k, ss.echo_width, ss.n_out, ss.used_rows);
            (gens, traces, Some(rest), cm)
        }
        ComposeForm::Program => {
            /*
             * The compose gadget in its flat form, recorded on its own witness
             * row the way the prover evaluates it: every constraint value is
             * an output pinned to zero, every slot an input wired from where
             * the assembly keeps it, and the region is three columns wide.
             */
            std::eprintln!("[asm] compose gen");
            let (cregion, ctrace) = compose_step::compose_gen_region(inner);
            let mut cm = ComposeMeta::of(&cregion, Vec::new());
            let width_c = Air::trace_width(&cregion);
            Rec::<Fp>::start();
            let cells: Vec<Rec<Fp>> = (0..width_c).map(|i| Rec::input(i, ctrace[i])).collect();
            let outs: Vec<Rec<Fp>> = cregion.transition_gen::<Rec<Fp>>(&cells, &[]);
            let tape = Rec::<Fp>::take();
            let outputs: Vec<u32> = outs.iter().map(|r| r.id()).collect();
            let eval = LineEval::new_base(tape.program(&outputs));
            let etrace = eval.trace();
            let mut c_rows = alloc::vec![0usize; width_c];
            for (k, row) in eval.input_rows() {
                c_rows[k] = row;
            }
            cm.c_rows = c_rows;
            cm.eval_cycles = eval
                .classes()
                .iter()
                .flat_map(|cls| cls[1..].iter().map(move |&rd| (cls[0], rd)))
                .collect();
            std::eprintln!(
                "[asm] compose as a program: {} steps in {} rows",
                eval.program().ops.len(),
                eval.rows()
            );
            let gens: Vec<OuterRegion<A>> = alloc::vec![OuterRegion::Eval(Arc::new(eval))];
            let traces: Vec<Vec<Fp>> = alloc::vec![etrace];
            (gens, traces, None, cm)
        }
    }
}
