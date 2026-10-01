// NONOS Operating System (AGPL-3.0-or-later)
//! Which of the launch circuit's periodic columns a verifier could compute
//! instead of opening them.
//!
//! The sidecar opens every periodic column at every query under the baked
//! root, about 1.3 KB a query. A column the verifier can evaluate itself at
//! a query point and at z costs no bytes. That is cheap only for a few shapes:
//! a constant, a column of short period P (a polynomial of degree below P in
//! x^(t/P)), or a column affine in x. This prints each column's shape so the
//! classification is measured, not argued.

use crate::crypto::stark::air::Air;
use crate::crypto::stark::field::Fp;
use crate::shield::join::join_split_shape;
use crate::shield::member::TREE_DEPTH;
use crate::shield_params::direct;

const PUBLICS: &str = include_str!("../../spec/wallet-vectors/transfer-eth/publics.json");

fn words() -> Vec<Fp> {
    let open = PUBLICS.find('[').unwrap_or(0) + 1;
    let close = PUBLICS[open..].find(']').map(|i| open + i).unwrap_or(open);
    PUBLICS[open..close]
        .split(',')
        .filter_map(|w| w.trim().parse().ok())
        .map(Fp::from_u64)
        .collect()
}

/// The least power of two P with `col[i] == col[i % P]` everywhere.
fn period(col: &[Fp]) -> usize {
    let mut p = 1usize;
    while p < col.len() {
        if (p..col.len()).all(|i| col[i] == col[i % p]) {
            return p;
        }
        p <<= 1;
    }
    col.len()
}

/// Maximal runs of one value: a step column with few runs is cheap to state.
fn runs(col: &[Fp]) -> usize {
    1 + col.windows(2).filter(|w| w[0] != w[1]).count()
}

#[test]
#[ignore = "analysis: prints the launch circuit's periodic columns by shape"]
fn print_the_periodic_columns_by_shape() {
    let air = join_split_shape(TREE_DEPTH, &words());
    let cols = air.periodic_columns();
    let t = 1usize << air.log_trace_len();
    let w = air.wired();
    let kinds = w.kind_map();
    let n_kinds = kinds.len();
    let sigma = w.permutation_columns().2;
    println!(
        "t = 2^{}, {} periodic columns, {} kinds, sigma base {:?}, rate 2^-{}",
        air.log_trace_len(),
        cols.len(),
        n_kinds,
        sigma,
        1 + direct::EXTRA_BLOWUP_BITS
    );
    let owner = |c: usize| -> String {
        if c < n_kinds {
            return format!("selector of kind {c}");
        }
        for (k, &(first, n, _, _, _)) in kinds.iter().enumerate() {
            if c >= first && c < first + n {
                return format!("kind {k} slot {}", c - first);
            }
        }
        "wiring".into()
    };
    let (mut constant, mut short, mut binary_steps, mut rest) = (0, 0, 0, 0);
    println!("col | owner | period | runs | distinct<=64 | binary | class");
    for (c, col) in cols.iter().enumerate() {
        assert_eq!(col.len(), t);
        let p = period(col);
        let r = runs(col);
        let mut distinct: Vec<u64> = Vec::new();
        for v in col {
            let v = v.to_u64();
            if !distinct.contains(&v) {
                distinct.push(v);
                if distinct.len() > 64 {
                    break;
                }
            }
        }
        let binary = distinct.iter().all(|&v| v <= 1);
        let class = if p == 1 {
            constant += 1;
            "constant"
        } else if p <= 64 {
            short += 1;
            "short period"
        } else if binary && r <= 16 {
            binary_steps += 1;
            "selector, few runs"
        } else {
            rest += 1;
            "open it"
        };
        println!(
            "{c} | {} | {p} | {r} | {} | {binary} | {class}",
            owner(c),
            distinct.len().min(65)
        );
    }
    println!("constant {constant}, short period {short}, selector with few runs {binary_steps}, the rest {rest}");
}

/// Per kind: where its instances start, how tall they are, and each of its
/// columns' period inside one instance. A kind whose columns are periodic
/// inside the region and whose instances all start on a multiple of that
/// period can have its columns extended over the whole trace; the selector
/// already gates its constraints everywhere else.
#[test]
#[ignore = "analysis: prints each kind's placement and in-region periods"]
fn print_the_kinds_in_region_periods() {
    let air = join_split_shape(TREE_DEPTH, &words());
    let cols = air.periodic_columns();
    let w = air.wired();
    let kinds = w.kind_map();
    let n_kinds = kinds.len();
    // An instance is a run of its kind's selector, which is on for all its rows
    // but the last: the run plus one is the region's height.
    for (k, &(first, n, _, instances, width)) in kinds.iter().enumerate() {
        let sel = &cols[k];
        let mut starts: Vec<(usize, usize)> = Vec::new();
        let mut r = 0usize;
        while r < sel.len() {
            if sel[r] == Fp::ONE {
                let s = r;
                while r < sel.len() && sel[r] == Fp::ONE {
                    r += 1;
                }
                starts.push((s, r - s + 1));
            } else {
                r += 1;
            }
        }
        let offs: Vec<String> = starts.iter().map(|(s, h)| format!("{s}(mod32 {}) h{h}", s % 32)).collect();
        println!("kind {k}: {instances} instances, width {width}, {n} columns; {}", offs.join(", "));
        if let Some(&(s, h)) = starts.first() {
            for (c, col) in cols.iter().enumerate().skip(first).take(n) {
                let local = &col[s..s + h];
                let full = period(local);
                // Also the period of the region less its last two rows, which
                // is where a region's closing rows usually sit.
                let body = period(&local[..h.saturating_sub(2).max(1)]);
                println!("  col {c} (slot {}): period in region {full}, without the last two rows {body}", c - first);
            }
        }
    }
    let _ = n_kinds;
}

/// Whether the Poseidon kinds carry one set of round constants: for each pair
/// of kinds, whether slot j of one, read over its first instance, is the same
/// sequence as slot j of the other over its own. Equal sets can share one set
/// of columns, which is what makes computing them cheaper than opening them.
#[test]
#[ignore = "analysis: compares the Poseidon kinds' round-constant columns"]
fn print_whether_the_poseidon_kinds_share_constants() {
    let air = join_split_shape(TREE_DEPTH, &words());
    let cols = air.periodic_columns();
    let kinds = air.wired().kind_map();
    let first_row = |k: usize| cols[k].iter().position(|v| *v == Fp::ONE).expect("an instance");
    let slot = |k: usize, j: usize| -> Vec<u64> {
        let (base, _, _, _, _) = kinds[k];
        let s = first_row(k);
        cols[base + j][s..s + 32].iter().map(|v| v.to_u64()).collect()
    };
    for (a, b) in [(1usize, 2usize), (1, 4), (1, 5), (2, 5), (4, 5)] {
        let same = (0..8).filter(|&j| slot(a, j) == slot(b, j)).count();
        println!("kinds {a} and {b}: {same} of 8 round-constant slots equal over one permutation");
    }
}

/// Every slot of kinds that share a shape, over the rows both regions have:
/// which columns are the same schedule and could be one column.
#[test]
#[ignore = "analysis: compares every slot of same-shaped kinds"]
fn print_which_slots_same_shaped_kinds_share() {
    let air = join_split_shape(TREE_DEPTH, &words());
    let cols = air.periodic_columns();
    let kinds = air.wired().kind_map();
    let run = |k: usize| -> (usize, usize) {
        let s = cols[k].iter().position(|v| *v == Fp::ONE).expect("an instance");
        let h = cols[k][s..].iter().take_while(|v| **v == Fp::ONE).count() + 1;
        (s, h)
    };
    for (a, b) in [(1usize, 4usize), (2, 5), (1, 2)] {
        let ((sa, ha), (sb, hb)) = (run(a), run(b));
        let h = ha.min(hb);
        let n = kinds[a].1.min(kinds[b].1);
        let same: Vec<usize> = (0..n)
            .filter(|&j| cols[kinds[a].0 + j][sa..sa + h] == cols[kinds[b].0 + j][sb..sb + h])
            .collect();
        println!("kinds {a} (h {ha}) and {b} (h {hb}): slots equal over {h} rows: {same:?} of {n}");
    }
}
