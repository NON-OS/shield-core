// NONOS Operating System (AGPL-3.0-or-later)

use super::air::{ActivityCount, SLOTS};
use crate::air::spec::Air;
use crate::field::Fp;

fn region(live: [bool; SLOTS], pos: [u64; SLOTS]) -> ActivityCount {
    let root = [11, 22, 33, 44];
    let walked = core::array::from_fn(|j| {
        if live[j] {
            root
        } else {
            [9, 9, 9, (j + 1) as u64]
        }
    });
    ActivityCount {
        log_t: 2,
        live,
        pos,
        walked,
        root,
    }
}

fn holds(r: &ActivityCount, t: &[Fp]) -> bool {
    let w = ActivityCount::WIDTH;
    let rows = 1usize << r.log_t;
    (0..rows - 1).all(|i| {
        r.transition(&t[i * w..(i + 2) * w], &[])
            .iter()
            .all(|v| *v == Fp::ZERO)
    })
}

#[test]
fn honest_claims_hold() {
    for (live, pos) in [
        ([true, false, false, false], [7, 0, 0, 0]),
        ([true, true, false, false], [3, 9, 0, 0]),
        ([true, true, true, true], [0, 1, 2, 65_535]),
    ] {
        let r = region(live, pos);
        assert!(holds(&r, &r.trace()), "{live:?} {pos:?}");
    }
}

/// The repeat the region exists for: one spend counted twice, at one position.
#[test]
fn a_repeated_or_falling_position_is_refused() {
    for pos in [[5, 5, 0, 0], [9, 3, 0, 0]] {
        let r = region([true, true, false, false], pos);
        let mut t = r.trace();
        let w = ActivityCount::WIDTH;
        // The honest gap for a repeat or a fall does not exist below 2^16; the
        // trace writes the field's wrap, which the range region refuses. Here
        // the region alone must still relate the cells: check the gap cell is
        // the wrapped value, which no 16-bit range admits.
        let g = t[ActivityCount::GAP].to_u64();
        assert!(
            g >= 1 << 16,
            "a repeat or fall left a gap a 16-bit range would admit: {g}"
        );
        assert!(holds(&r, &t));
        t[ActivityCount::GAP] = Fp::ZERO;
        for i in 0..(1 << r.log_t) {
            t[i * w + ActivityCount::GAP] = Fp::ZERO;
        }
        assert!(
            !holds(&r, &t),
            "a zero gap was accepted for positions {pos:?}"
        );
    }
}

#[test]
fn every_rule_bites() {
    let r = region([true, true, false, false], [3, 9, 0, 0]);
    let w = ActivityCount::WIDTH;
    let base = r.trace();
    let rows = 1usize << r.log_t;
    let set = |col: usize, v: u64| {
        let mut t = base.clone();
        for i in 0..rows {
            t[i * w + col] = Fp::from_u64(v);
        }
        t
    };
    assert!(
        !holds(&r, &set(ActivityCount::LIVE, 2)),
        "a live cell that is not a bit"
    );
    assert!(
        !holds(&r, &set(ActivityCount::LIVE + 3, 1)),
        "a live slot after a dead one"
    );
    assert!(!holds(&r, &set(ActivityCount::K, 3)), "a wrong count");
    assert!(
        !holds(&r, &set(ActivityCount::GAP + 2, 1)),
        "a gap behind a dead slot"
    );
    assert!(
        !holds(&r, &set(ActivityCount::walked_col(1, 0), 12)),
        "a live walk off the root"
    );
    assert!(
        holds(&r, &set(ActivityCount::walked_col(3, 0), 12)),
        "a dead walk is free"
    );
    let none = region([true, false, false, false], [1, 0, 0, 0]);
    let mut t = none.trace();
    for i in 0..(1 << none.log_t) {
        t[i * w + ActivityCount::LIVE] = Fp::ZERO;
        t[i * w + ActivityCount::K] = Fp::ZERO;
        t[i * w + ActivityCount::walked_col(0, 0)] = Fp::from_u64(1);
    }
    assert!(!holds(&none, &t), "a claim of no spend at all");
}
