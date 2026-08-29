//! plan_wire_contract.rs — the Rust (interpreter) half of the Go↔Rust cofre serde
//! contract (GEN TYPED-SPEC CONTRACT applied to the emitter → cofre-types border).
//!
//! A sibling Go emitter (`cofre_plan.go`) hand-mirrors cofre-types' serde schema
//! field-for-field and freezes the exact wire artifact into its own
//! `testdata/cofre-plan.golden.json`. That Go-side golden was only guarded by golden
//! SUBSTRINGS on the Go side — which proves the Go BYTES but never that the REAL
//! cofre-types crate deserializes them. A rename here in cofre-types
//! (`test_only` → `testing_only`, the `pre-shared-key` tag, the `PasswordRandom`
//! variant, …) stayed green in Go while `cofre apply --manifest` would break at RUNTIME.
//!
//! This test closes that: it deserializes the frozen Go wire shape through the REAL
//! [`SecretMaterializationPlan`] type. A cofre-types change that would break the live
//! `cofre apply --manifest` now fails `cargo test -p cofre-types` — CI-caught, not a
//! runtime break. The fixture below is byte-identical to the emitter's golden (the two
//! are held in lockstep by the emitter repo's `-update` seeding plus its cross-repo
//! byte-identity test, which soft-skips when this repo is not a sibling checkout).
//!
//! ── ★ THE FIXTURE NAMES A POSTURE, NOT AN ESTATE ─────────────────────────────────
//! The frozen plan is the canonical REFERENCE ENVIRONMENT the emitter's
//! `CofrePlanFor(testEnv())` produces. It used to carry one private deployment's
//! codename in `metadata.name`, in every akeyless path and in every label. Those values
//! are the emitter's to choose and were never part of what this contract PROVES, which
//! is the serde MAPPING — so naming an estate bought nothing and leaked something. They
//! are now `reference-env`.
//!
//! Every expectation that used to restate one of those values now READS IT BACK OUT OF
//! THE FIXTURE (see [`wire_string`]). A restated literal is free to disagree with the
//! bytes it exists to pin, and that is exactly how a guard drifts through a rename;
//! deriving the expectation makes the disagreement unrepresentable and keeps the test
//! green across a future re-seed under any environment name. The literals that remain
//! (`24`, `alphanumeric`, `32`, the secret NAMES) are properties of the schema and the
//! components, not of any estate, so they stay stated.
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

/// The frozen wire artifact — byte-identical to the Go emitter's
/// `testdata/cofre-plan.golden.json` (the exact `marshalIndent` output `emitCofrePlan`
/// ships as the `ArtifactCofrePlan` blob).
const REFERENCE_GOLDEN: &str = include_str!("testdata/reference-cofre-plan.golden.json");

/// The frozen fixture as raw JSON — the single source every derived expectation reads.
fn fixture() -> Value {
    serde_json::from_str(REFERENCE_GOLDEN).expect("the frozen fixture must be valid JSON")
}

/// Read a string out of the fixture by JSON Pointer, so an expected value is never a
/// literal that can drift from the bytes it guards. An absent/non-string pointer is a
/// wire-shape change and fails loudly rather than defaulting to something plausible.
fn wire_string(v: &Value, ptr: &str) -> String {
    v.pointer(ptr)
        .and_then(Value::as_str)
        .unwrap_or_else(|| {
            panic!("the frozen fixture has no string at `{ptr}` — the wire shape changed")
        })
        .to_owned()
}

/// The fixture's raw entry for one secret, located the same way the typed side locates
/// it (by `name`), so the derived expectation and the typed lookup cannot address
/// different secrets.
fn wire_secret(v: &Value, name: &str) -> Value {
    v["secrets"]
        .as_array()
        .expect("the frozen fixture must carry a `secrets` array")
        .iter()
        .find(|s| s["name"] == name)
        .unwrap_or_else(|| panic!("the frozen fixture is missing the {name:?} secret"))
        .clone()
}

/// Tier 2 — the frozen Go wire shape deserializes through the REAL type and validates.
/// A required-field rename, a wire-tag rename, or a field type change breaks here.
#[test]
fn wire_shape_deserializes_through_real_type() {
    let plan: SecretMaterializationPlan =
        serde_json::from_str(REFERENCE_GOLDEN).unwrap_or_else(|e| {
            panic!(
                "the frozen cofre plan no longer deserializes through the real \
             SecretMaterializationPlan — a rename/type-change in cofre-types would break \
             `cofre apply --manifest` at runtime: {e}"
            )
        });
    plan.validate()
        .unwrap_or_else(|e| panic!("the frozen cofre plan fails cofre-types validation: {e}"));

    // The canonical border invariants (== the Go emitter's CofrePlanFor(testEnv())).
    assert_eq!(plan.api_version, SecretMaterializationPlan::API_VERSION);
    assert_eq!(plan.kind, SecretMaterializationPlan::KIND);
    assert!(!plan.test_only, "born plans are never test_only");
    // Derived, not restated: the typed field must carry exactly the wire field's value.
    assert_eq!(plan.metadata.name, wire_string(&fixture(), "/metadata/name"));
    assert!(!plan.secrets.is_empty());
}

/// Tier 1 — the three gen policies + the akeyless backend + rotation the reference plan
/// depends on survive as the REAL typed variants. A variant/field RENAME in cofre-types
/// makes this fail to COMPILE (the strongest tier); a semantic drift (wrong
/// length/charset) fails the assertion. This is where a `PasswordRandom` →
/// `RandomPassword` rename is a compile error, not a runtime `cofre apply` failure.
#[test]
fn typed_policies_survive_the_border() {
    let fx = fixture();
    let plan: SecretMaterializationPlan = serde_json::from_str(REFERENCE_GOLDEN).unwrap();
    let by_name = |n: &str| {
        plan.secrets
            .iter()
            .find(|s| s.name == n)
            .unwrap_or_else(|| panic!("the reference plan is missing the {n:?} secret"))
    };

    // mysql-root-password -- akeyless backend, password-random(24, alphanumeric), quarterly.
    // (Worded with a dash, not a colon: `password: <8+ chars>` is the shape the fleet's
    // pre-commit credential gate refuses, and a comment is not worth teaching people to
    // reach for --no-verify. The prose carried over verbatim from the pre-rename file.)
    let mysql = by_name("mysql-root-password");
    match &mysql.backend {
        BackendKind::Akeyless { path } => {
            // Derived from the fixture: the estate a path names is the emitter's choice,
            // the MAPPING of `backend.path` onto this field is what this test owns.
            assert_eq!(
                path,
                &wire_string(&wire_secret(&fx, "mysql-root-password"), "/backend/path")
            );
        }
        other => panic!("mysql-root-password must be an Akeyless backend, got {other:?}"),
    }
    match &mysql.generation {
        Some(SecretGenPolicy::PasswordRandom {
            length, charset, ..
        }) => {
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
    let fixture: Value = serde_json::from_str(REFERENCE_GOLDEN).unwrap();
    let plan: SecretMaterializationPlan = serde_json::from_str(REFERENCE_GOLDEN).unwrap();
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
