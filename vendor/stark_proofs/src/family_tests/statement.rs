// NONOS Operating System (AGPL-3.0-or-later)

use crate::recursion_assembly::{assemble_capped, Tamper};
use crate::witness_satisfies::satisfies;

/// A drawn index is the element the transcript squeezed, all 64 bits of it.
/// The block under it is honest, its bits and its point are the ones an
/// honest draw gives, and only the draw's recovered element disagrees with
/// the squeeze cell: before the draws were bound, this assembled and
/// satisfied, and the inner's query positions were whatever the prover said.
#[test]
fn a_draw_off_the_transcript_rejects() {
    for tamper in [Tamper::DrawOffTranscript, Tamper::FriDrawOffTranscript] {
        let asm = assemble_capped(tamper, 0, 2);
        assert!(
            !satisfies(&asm.wired, &asm.witness),
            "a draw the transcript never made verified"
        );
    }
}

/// The statement family: the DEEP batching coefficients are the ones the STARK
/// transcript squeezed. A free coefficient batches just as well, which is the
/// whole point of binding them.
#[test]
fn an_unsqueezed_batching_coefficient_rejects() {
    let asm = assemble_capped(Tamper::OffTranscriptCoeff, 0, 2);
    assert!(
        !satisfies(&asm.wired, &asm.witness),
        "a DEEP coefficient the transcript never squeezed verified"
    );
}
