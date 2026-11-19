//! Composition inventory is authority-bearing backend evidence. Only the
//! adapters that inspect actual objects/state/materialization may construct
//! its opaque carrier. Reject constructor references through aliases too.
//! Shared tokenization excludes comments, strings and test-only code. This is
//! a source guard, not Rust name resolution; keep the unique constructor name.

use intentd_test_support::source_lint::{test_code_files, tokenize, workspace_root, TestCodeText};

const OWNERS: &[&str] = &[
    "crates/intent-core/src/work_evidence/composition.rs",
    "crates/intent-atomic/src/composition.rs",
    "crates/intent-git/src/engine/composition.rs",
];

const ADOPTION_BACKENDS: &[&str] = &[
    "crates/intent-core/src/vcs/adoption.rs",
    "crates/intent-git/src/engine/adoption.rs",
];
const ADOPTION_STORE: &[&str] = &[
    "crates/intent-core/src/vcs/adoption.rs",
    "crates/intent-store/src/work_confirmation/source_adoption.rs",
];
const WRITE_BARRIER_OWNERS: &[&str] = &[
    "crates/intent-core/src/vcs/adoption.rs",
    "crates/intent-services/src/work_adoption_barrier.rs",
];

fn owners(constructor: &str) -> Option<&'static [&'static str]> {
    match constructor {
        "from_verified_backend" => Some(OWNERS),
        "from_captured_target"
        | "from_prepared_adoption"
        | "from_observed_adoption"
        | "from_observed_adoption_progress" => Some(ADOPTION_BACKENDS),
        "from_accepted_store_decision" => Some(ADOPTION_STORE),
        "from_admitted_write_barrier" => Some(WRITE_BARRIER_OWNERS),
        _ => None,
    }
}

fn violations(path: &str, source: &str, whole_test: bool) -> Vec<usize> {
    if whole_test {
        return vec![];
    }
    let text = TestCodeText::new(source, whole_test);
    tokenize(&text.chars)
        .into_iter()
        .filter(|token| {
            !text.in_test(token.start)
                && owners(&token.text).is_some_and(|allowed| !allowed.contains(&path))
        })
        .map(|token| token.line)
        .collect()
}

#[test]
fn only_inspecting_backend_owners_construct_composition_proof() {
    let hits: Vec<_> = test_code_files(&workspace_root())
        .into_iter()
        .flat_map(|file| {
            violations(&file.rel, &file.src, file.whole)
                .into_iter()
                .map(move |line| format!("{}:{line}", file.rel))
        })
        .collect();
    assert!(
        hits.is_empty(),
        "Composition proof construction must stay in inspecting backend adapters:\n{}",
        hits.join("\n")
    );
}

#[test]
fn services_cannot_mint_proof_from_serialized_data_or_an_aliased_function() {
    let source = "fn forge() { let f = Alias::from_verified_backend; f(dto); }";
    assert_eq!(
        violations("crates/intent-services/src/new_owner.rs", source, false),
        [1]
    );
    assert!(violations(OWNERS[1], source, false).is_empty());
}

#[test]
fn comments_strings_and_test_items_are_not_production_owners() {
    let source = r#"
// Alias::from_verified_backend(dto)
fn description() { let text = "from_verified_backend"; }
#[cfg(test)] mod tests { fn fixture() { Alias::from_verified_backend(dto); } }
"#;
    assert!(violations("crates/intent-services/src/new_owner.rs", source, false).is_empty());
}

#[test]
fn adoption_barrier_store_authorization_and_native_observation_have_distinct_owners() {
    let backend = "fn inspect() { Alias::from_observed_adoption(data,path,false); }";
    assert!(violations(ADOPTION_BACKENDS[1], backend, false).is_empty());
    assert_eq!(violations(ADOPTION_STORE[1], backend, false), [1]);
    let store = "fn accept() { let create=Alias::from_accepted_store_decision; create(data); }";
    assert!(violations(ADOPTION_STORE[1], store, false).is_empty());
    assert_eq!(violations(ADOPTION_BACKENDS[1], store, false), [1]);
    let barrier = "fn close_and_drain() { Alias::from_admitted_write_barrier(root,op,live); }";
    assert!(violations(WRITE_BARRIER_OWNERS[1], barrier, false).is_empty());
    assert_eq!(violations(ADOPTION_BACKENDS[1], barrier, false), [1]);
}
