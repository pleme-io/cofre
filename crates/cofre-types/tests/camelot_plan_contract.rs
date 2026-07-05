//! camelot_plan_contract.rs — the Rust (interpreter) half of the Go↔Rust cofre serde
//! contract (GEN TYPED-SPEC CONTRACT applied to the camelot → cofre-types border).
//!
//! camelot-bootstrap's Go emitter (`cofre_plan.go`) hand-mirrors cofre-types' serde
//! schema field-for-field and freezes the exact wire artifact into
//! `camelot-bootstrap/testdata/cofre-plan.golden.json`. That Go-side golden was only
//! guarded by golden SUBSTRINGS on the Go side — which proves the Go BYTES but never
//! that the REAL cofre-types crate deserializes them. A rename here in cofre-types
//! (`test_only` → `testing_only`, the `pre-shared-key` tag, the `PasswordRandom`
//! variant, …) stayed green in Go while `cofre apply --manifest` would break at RUNTIME.
//!
//! This test closes that: it deserializes the frozen Go wire shape through the REAL
//! [`SecretMaterializationPlan`] type. A cofre-types change that would break the live
//! `cofre apply --manifest` now fails `cargo test -p cofre-types` — CI-caught, not a
//! runtime break. The fixture below is byte-identical to the Go golden (the two are held
//! in lockstep by `camelot-bootstrap/cofre_contract_test.go`'s `-update` seeding + its
//! `TestCofrePlan_ContractFixtureSharedWithCofre`).
//!
//! THREE tiers of catch, stated honestly (never rounded up):
//!   1. truly-unrepresentable (compile error) — the typed assertions below name the real
//!      variants/fields (`SecretGenPolicy::PasswordRandom { length, charset, .. }`,
//!      `BackendKind::Akeyless { path }`). A variant/field RENAME in cofre-types makes
//!      THIS test fail to COMPILE (E0599/E0433/E0026), the strongest tier.
//!   2. parse-time-rejected (`Err` at deserialize) — a wire-tag rename, a REQUIRED-field
//!      rename/removal (`apiVersion`/`kind`/`metadata`/`secrets`/`name`/`backend`), or a
//!      field TYPE change makes the frozen fixture fail to deserialize.
//!   3. only-mitigated → parse-boundary — an OPTIONAL-field rename (`test_only`, `rotation`,
//!      `description`, `source`, `labels`, `generation`; all `#[serde(default)]` /
//!      skip-if-none) is silently absorbed by serde defaults. `wire_keys_survive_round_trip`
//!      catches it: a fixture key that no longer maps to a live field vanishes on
//!      deserialize→reserialize.

use cofre_types::{BackendKind, RotationPolicy, SecretGenPolicy, SecretMaterializationPlan};
use serde_json::Value;

/// The frozen Camelot wire artifact — byte-identical to
/// `camelot-bootstrap/testdata/cofre-plan.golden.json` (the exact `marshalIndent`
/// output `emitCofrePlan` ships as the `ArtifactCofrePlan` blob).
const CAMELOT_GOLDEN: &str = include_str!("testdata/camelot-cofre-plan.golden.json");

/// Tier 2 — the frozen Go wire shape deserializes through the REAL type and validates.
/// A required-field rename, a wire-tag rename, or a field type change breaks here.
#[test]
fn camelot_wire_shape_deserializes_through_real_type() {
    let plan: SecretMaterializationPlan = serde_json::from_str(CAMELOT_GOLDEN).unwrap_or_else(|e| {
        panic!(
            "the frozen Camelot cofre plan no longer deserializes through the real \
             SecretMaterializationPlan — a rename/type-change in cofre-types would break \
             `cofre apply --manifest` at runtime: {e}"
        )
    });
    plan.validate().unwrap_or_else(|e| {
        panic!("the frozen Camelot cofre plan fails cofre-types validation: {e}")
    });

    // The canonical border invariants (== camelot-bootstrap CofrePlanFor(testEnv())).
    assert_eq!(plan.api_version, SecretMaterializationPlan::API_VERSION);
    assert_eq!(plan.kind, SecretMaterializationPlan::KIND);
    assert!(!plan.test_only, "born plans are never test_only");
    assert_eq!(plan.metadata.name, "camelot");
    assert!(!plan.secrets.is_empty());
}

/// Tier 1 — the three gen policies + the akeyless backend + rotation Camelot depends on
/// survive as the REAL typed variants. A variant/field RENAME in cofre-types makes this
/// fail to COMPILE (the strongest tier); a semantic drift (wrong length/charset) fails the
/// assertion. This is where a `PasswordRandom` → `RandomPassword` rename is a compile error,
/// not a runtime `cofre apply` failure.
#[test]
fn camelot_typed_policies_survive_the_border() {
    let plan: SecretMaterializationPlan = serde_json::from_str(CAMELOT_GOLDEN).unwrap();
    let by_name = |n: &str| {
        plan.secrets
            .iter()
            .find(|s| s.name == n)
            .unwrap_or_else(|| panic!("Camelot plan is missing the {n:?} secret"))
    };

    // mysql-root-password: akeyless backend + password-random(24, alphanumeric) + quarterly.
    let mysql = by_name("mysql-root-password");
    match &mysql.backend {
        BackendKind::Akeyless { path } => {
            assert_eq!(path, "/camelot/camelot/mysql/root-password");
        }
        other => panic!("mysql-root-password must be an Akeyless backend, got {other:?}"),
    }
    match &mysql.generation {
        Some(SecretGenPolicy::PasswordRandom { length, charset, .. }) => {
            assert_eq!(*length, 24);
            assert_eq!(*charset, cofre_types::Charset::Alphanumeric);
        }
        other => panic!("mysql-root-password must be PasswordRandom, got {other:?}"),
    }
    assert_eq!(mysql.rotation, RotationPolicy::Quarterly);

    // db-encryption-key: pre-shared-key(32) — the interim DEK material.
    match &by_name("db-encryption-key").generation {
        Some(SecretGenPolicy::PreSharedKey { length_bytes }) => assert_eq!(*length_bytes, 32),
        other => panic!("db-encryption-key must be PreSharedKey, got {other:?}"),
    }
    assert_eq!(by_name("db-encryption-key").rotation, RotationPolicy::Never);

    // rustfs-access-key: token(20).
    match &by_name("rustfs-access-key").generation {
        Some(SecretGenPolicy::Token { length, .. }) => assert_eq!(*length, 20),
        other => panic!("rustfs-access-key must be a Token, got {other:?}"),
    }

    // Tier-honesty preserved through the typed border: operator/ceremony-owned materials
    // carry NO generation policy — cofre tracks + verifies, never births them.
    for operator_owned in [
        "gateway-access-id",
        "gateway-access-key",
        "uam-api-key",
        "uam-access-id",
    ] {
        assert!(
            by_name(operator_owned).generation.is_none(),
            "operator-owned {operator_owned:?} must have generation:none (cofre does not birth it)"
        );
    }
}

/// Tier 3 — every wire key in the frozen Go fixture must survive a round-trip through the
/// real type. This is what catches an OPTIONAL-field rename that serde defaults would
/// otherwise absorb silently: a renamed field's OLD key is dropped on deserialize (unknown)
/// and never re-emitted, so it vanishes from the reserialized value.
///
/// The one known, honest asymmetry: `PasswordRandom.max_length` has no
/// `skip_serializing_if`, so Rust re-emits `"max_length": null` where Go elides it. The
/// subset direction (fixture-keys ⊆ reserialized-keys) tolerates that extra key by design —
/// it flags only keys the fixture has that the round-trip LOSES.
#[test]
fn wire_keys_survive_round_trip() {
    let fixture: Value = serde_json::from_str(CAMELOT_GOLDEN).unwrap();
    let plan: SecretMaterializationPlan = serde_json::from_str(CAMELOT_GOLDEN).unwrap();
    let reserialized: Value = serde_json::to_value(&plan).unwrap();
    assert_wire_keys_survive(&fixture, &reserialized, "$");
}

/// Recursively assert every key present in `fixture` still exists in `reserialized`
/// (values are NOT compared — Go HTML-escapes `<`/`>`, Rust does not; only KEY survival
/// is the contract). Arrays round-trip element-wise at equal length.
fn assert_wire_keys_survive(fixture: &Value, reserialized: &Value, path: &str) {
    match (fixture, reserialized) {
        (Value::Object(fo), Value::Object(ro)) => {
            for (k, fv) in fo {
                let rv = ro.get(k).unwrap_or_else(|| {
                    panic!(
                        "wire key `{path}.{k}` in the frozen Go fixture is GONE after a \
                         round-trip through the real cofre-types type — a rename/removal in \
                         cofre-types would break `cofre apply --manifest`. Change the border \
                         deliberately (regenerate BOTH goldens) or revert the rename."
                    )
                });
                assert_wire_keys_survive(fv, rv, &format!("{path}.{k}"));
            }
        }
        (Value::Array(fa), Value::Array(ra)) => {
            assert_eq!(
                fa.len(),
                ra.len(),
                "array length changed on round-trip at `{path}`"
            );
            for (i, (fv, rv)) in fa.iter().zip(ra.iter()).enumerate() {
                assert_wire_keys_survive(fv, rv, &format!("{path}[{i}]"));
            }
        }
        (Value::Object(_) | Value::Array(_), _) => panic!(
            "wire shape kind changed at `{path}`: fixture is a container, round-trip is a scalar"
        ),
        // scalar vs scalar (or the round-trip added structure) — no key to lose.
        _ => {}
    }
}
