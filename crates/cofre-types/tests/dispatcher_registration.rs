//! Verify cofre-types registers BackendKind into gen-platform's
//! fleet-wide DispatcherCatalog. cofre is the FOURTH consumer
//! class adopting the typed-dispatcher catamorphism (after gen
//! adapters + caixa OTP + wasm-platform).
//!
//! BackendKind is the typed secret-source surface — Sops / Akeyless
//! / Mock. The substrate's typed shadow now spans:
//!
//!   - Code supply (gen adapter quirks)
//!   - Hot upgrades (caixa OTP)
//!   - Runtime sandbox (wasm-platform WASI/WASM)
//!   - Secret materialization (cofre backend-kind) ← THIS
//!
//! ...all sharing the four algebraic laws
//! (saturation/determinism/idempotence/closure under composition).

use cofre_types::BackendKind;
use gen_platform::{catalog, TypedDispatcherTrait};

#[test]
fn backend_kind_registers_into_fleet_catalog() {
    let entry = catalog::by_label("cofre.backend-kind")
        .expect("cofre-types must register BackendKind");
    assert_eq!(entry.label, "cofre.backend-kind");
    assert_eq!((entry.variant_count)(), 3);
}

#[test]
fn backend_kind_variants_kebab() {
    let kinds = BackendKind::variant_kinds();
    assert_eq!(kinds, vec!["sops", "akeyless", "mock"]);
}

#[test]
fn backend_kind_variant_fields_surfaced() {
    let fields = BackendKind::variant_fields();
    assert_eq!(
        fields,
        vec![
            ("sops", vec!["file", "yaml_path"]),
            ("akeyless", vec!["path"]),
            ("mock", vec!["name"]),
        ]
    );
}

#[test]
fn backend_kind_serde_tags_match_reflection() {
    let samples = [
        (
            BackendKind::Sops {
                file: "/x.yaml".into(),
                yaml_path: "a.b".into(),
            },
            "sops",
        ),
        (
            BackendKind::Akeyless {
                path: "/p/q".into(),
            },
            "akeyless",
        ),
        (
            BackendKind::Mock {
                name: "test".into(),
            },
            "mock",
        ),
    ];
    let reflected = BackendKind::variant_kinds();
    for (sample, expected_kind) in &samples {
        let v: serde_json::Value = serde_json::to_value(sample).unwrap();
        assert_eq!(
            v.get("kind").and_then(|k| k.as_str()),
            Some(*expected_kind)
        );
        assert!(reflected.contains(expected_kind));
    }
}
