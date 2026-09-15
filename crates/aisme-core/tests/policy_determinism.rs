// SPDX-License-Identifier: Apache-2.0
//! `F1.PL.05`: same source → identical bytes, and the bytes do not depend on
//! how the source was arranged. Run by `cargo xtask test-policy-compiler`.

use aisme_core::policy::encode::{digest, encode, POLICY_ENCODING_VERSION};
use aisme_core::policy::{compile, parse, Bindings};

const SKETCH: &str = include_str!("fixtures/sketch.toml");

fn bindings() -> Bindings {
    Bindings::new()
        .with("workspace", "/home/u/proj")
        .with("home", "/home/u")
        .with_list(
            "session.network_allow",
            &["registry.npmjs.org", "api.anthropic.com"],
        )
}

fn bytes_of(src: &str, bindings: &Bindings) -> Vec<u8> {
    let policy = parse(src).unwrap_or_else(|e| panic!("{e:#?}"));
    let compiled = compile(&policy, bindings).unwrap_or_else(|e| panic!("{e:#?}"));
    encode(&compiled)
}

#[test]
fn the_same_source_gives_the_same_bytes_every_time() {
    let a = bytes_of(SKETCH, &bindings());
    for _ in 0..10 {
        assert_eq!(bytes_of(SKETCH, &bindings()), a);
    }
    assert_eq!(a[0], POLICY_ENCODING_VERSION);
    let policy = parse(SKETCH).unwrap();
    let compiled = compile(&policy, &bindings()).unwrap();
    assert_eq!(digest(&compiled), digest(&compiled));
}

#[test]
fn the_bytes_do_not_depend_on_the_order_the_source_was_written_in() {
    // Reverse the order of every [[rule]] block; the bindings and every rule
    // are the same, so the compiled bytes must be.
    let mut blocks: Vec<&str> = SKETCH.split("\n[[").collect();
    let head = blocks.remove(0);
    blocks.reverse();
    let reversed = core::iter::once(head.to_owned())
        .chain(blocks.iter().map(|b| format!("[[{b}")))
        .collect::<Vec<_>>()
        .join("\n");
    assert_ne!(reversed, SKETCH);
    assert_eq!(
        bytes_of(&reversed, &bindings()),
        bytes_of(SKETCH, &bindings())
    );
    // And a list variable bound in another order resolves to the same bytes:
    // values are sorted before encoding.
    let swapped = Bindings::new()
        .with("workspace", "/home/u/proj")
        .with("home", "/home/u")
        .with_list(
            "session.network_allow",
            &["api.anthropic.com", "registry.npmjs.org"],
        );
    assert_eq!(bytes_of(SKETCH, &swapped), bytes_of(SKETCH, &bindings()));
}

#[test]
fn different_meaning_gives_different_bytes() {
    let base = bytes_of(SKETCH, &bindings());
    // A different workspace: the resolved prefix differs.
    let other_ws = Bindings::new()
        .with("workspace", "/srv/other")
        .with("home", "/home/u")
        .with_list(
            "session.network_allow",
            &["registry.npmjs.org", "api.anthropic.com"],
        );
    assert_ne!(bytes_of(SKETCH, &other_ws), base);
    // One verdict changed: one byte differs, and the digest with it.
    let stricter = SKETCH.replacen(
        "verdict = \"warn\"               # recorded",
        "verdict = \"deny\"               # recorded",
        1,
    );
    assert_ne!(stricter, SKETCH);
    assert_ne!(bytes_of(&stricter, &bindings()), base);
    let d1 = digest(&compile(&parse(SKETCH).unwrap(), &bindings()).unwrap());
    let d2 = digest(&compile(&parse(&stricter).unwrap(), &bindings()).unwrap());
    assert_ne!(d1, d2);
}
