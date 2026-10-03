// NONOS Operating System (AGPL-3.0-or-later)
//! The Lean models other crates hold their circuits to, as text, so a crate
//! that depends on this one at a pinned commit reads the model of that same
//! commit. A test elsewhere parses the `def name : Nat := value` lines and the
//! tables it needs and compares them with the circuit it builds.

/// `lean/Shield/Device.lean`: the anonymous device statement's layout, for
/// `nonos-device-attest`.
pub const DEVICE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../lean/Shield/Device.lean"
));

/// `lean/Shield/Attest.lean`: the attestation statement's layout.
pub const ATTEST: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../lean/Shield/Attest.lean"
));

/// The value of `def name : Nat := value` in a model, or `None`.
pub fn nat(model: &str, name: &str) -> Option<u64> {
    let key = alloc::format!("def {name} : Nat := ");
    let at = model.find(&key)? + key.len();
    model[at..].split_whitespace().next()?.parse().ok()
}

/// Every unsigned number between `def name` and the end of its list, in
/// order: the flattened tuples of a table such as `kindMap` or `wires`.
pub fn table(model: &str, name: &str) -> Option<alloc::vec::Vec<u64>> {
    let at = model.find(&alloc::format!("def {name} "))?;
    let rest = &model[at..];
    let open = rest.find(":=")?;
    let end = rest[open..].find("]\n").map(|e| open + e)?;
    Some(
        rest[open..end]
            .split(|c: char| !c.is_ascii_digit())
            .filter(|t| !t.is_empty())
            .filter_map(|t| t.parse().ok())
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_models_read_back() {
        assert_eq!(nat(DEVICE, "registryDepth"), Some(20));
        assert_eq!(nat(DEVICE, "logTrace"), Some(14));
        assert_eq!(
            table(DEVICE, "kindMap"),
            Some(alloc::vec![
                5, 11, 30, 1, 29, 16, 11, 30, 1, 29, 27, 11, 30, 1, 29, 38, 11, 30, 1, 29, 49, 0,
                0, 1, 1
            ])
        );
        assert_eq!(
            table(DEVICE, "offsets"),
            Some(alloc::vec![0, 320, 640, 1344, 1408])
        );
        assert_eq!(nat(ATTEST, "words"), Some(9));
        assert_eq!(table(ATTEST, "wires").map(|t| t.len()), Some(27));
    }
}
