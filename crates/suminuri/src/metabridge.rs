//! The `sops:` block ↔ [`Metadata`] bridge.
//!
//! Written by hand rather than derived, for a reason that is easy to miss:
//! **field order in the emitted block is byte order in the file**, and go-yaml
//! gets that order from a Go struct's declaration order. A serde derive over a
//! Rust struct would give the same guarantee only by accident, and any field
//! reordering — the kind a linter suggests — would silently reflow every sops
//! file in the fleet. Here the order is a literal list in [`to_tree`], with a test
//! that pins it against a real sops artifact.
//!
//! The other reason is that [`Metadata`] deliberately has no settable key arrays
//! (see `suminuri_wire::metadata`), so the round-trip is not a symmetric derive:
//! reading collects [`WrappedKey`]s, writing *projects* them back.

use suminuri_wire::{KeyProvider, Metadata, WrappedKey};
use suminuri_yaml::{Item, Scalar, ScalarStyle, Value};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MetaError {
    #[error("the file has no `sops:` metadata block; it is not an encrypted suminuri/sops file")]
    NoMetadata,
    #[error("`sops:` is present but is not a mapping")]
    MetadataNotAMapping,
    #[error("`sops.{field}` is required and missing")]
    MissingField { field: &'static str },
    #[error("`sops.{provider}[{index}]` is missing its `{field}`")]
    MalformedKey {
        provider: &'static str,
        index: usize,
        field: &'static str,
    },
}

/// Every provider array we read, with the field that names the recipient.
///
/// A table rather than seven copies of the same loop — and the reason it covers
/// providers we cannot *unwrap* is that a file must round-trip intact even then.
/// Dropping a KMS key on write would silently remove a recipient's access, which
/// is the worst possible failure for a tool aliased over sops.
const PROVIDER_TABLE: &[(KeyProvider, &str, &str)] = &[
    (KeyProvider::Pgp, "pgp", "fp"),
    (KeyProvider::AwsKms, "kms", "arn"),
    (KeyProvider::GcpKms, "gcp_kms", "resource_id"),
    (KeyProvider::HuaweiKms, "hckms", "key_id"),
    (KeyProvider::AzureKeyVault, "azure_kv", "vault_url"),
    (KeyProvider::HcVault, "hc_vault", "key_name"),
    (KeyProvider::Age, "age", "recipient"),
];

/// Read a `sops:` block into typed metadata.
pub fn from_tree(sops: &Value) -> Result<Metadata, MetaError> {
    let Value::Mapping(_) = sops else {
        return Err(MetaError::MetadataNotAMapping);
    };

    let s = |k: &'static str| -> Option<String> {
        sops.get(k).and_then(Value::as_str).map(str::to_string)
    };
    let lastmodified = s("lastmodified").ok_or(MetaError::MissingField {
        field: "lastmodified",
    })?;
    let mac = s("mac").ok_or(MetaError::MissingField { field: "mac" })?;

    let mut keys: Vec<WrappedKey> = Vec::new();
    for (provider, field, id_field) in PROVIDER_TABLE {
        let Some(Value::Sequence(entries)) = sops.get(field) else {
            continue;
        };
        for (index, entry) in entries.iter().enumerate() {
            let suminuri_yaml::Entry::Value(v) = entry else {
                continue;
            };
            let recipient =
                v.get(id_field)
                    .and_then(Value::as_str)
                    .ok_or(MetaError::MalformedKey {
                        provider: field,
                        index,
                        field: id_field,
                    })?;
            let enc = v
                .get("enc")
                .and_then(Value::as_str)
                .ok_or(MetaError::MalformedKey {
                    provider: field,
                    index,
                    field: "enc",
                })?;
            let created_at = v
                .get("created_at")
                .and_then(Value::as_str)
                .map(str::to_string);
            keys.push(if *provider == KeyProvider::Age {
                WrappedKey::age(recipient, enc)
            } else {
                WrappedKey::opaque(*provider, recipient, enc, created_at)
            });
        }
    }

    let mut m = Metadata::from_wrapped(keys, lastmodified, mac);
    m.unencrypted_suffix = s("unencrypted_suffix");
    m.encrypted_suffix = s("encrypted_suffix");
    m.unencrypted_regex = s("unencrypted_regex");
    m.encrypted_regex = s("encrypted_regex");
    m.unencrypted_comment_regex = s("unencrypted_comment_regex");
    m.encrypted_comment_regex = s("encrypted_comment_regex");
    m.mac_only_encrypted = sops.get("mac_only_encrypted").and_then(Value::as_str) == Some("true");
    m.shamir_threshold = sops
        .get("shamir_threshold")
        .and_then(Value::as_str)
        .and_then(|v| v.parse::<u32>().ok())
        .filter(|v| *v > 0);
    if let Some(v) = s("version") {
        m.version = v;
    }
    Ok(m)
}

/// Project typed metadata back into a `sops:` block.
///
/// **The order of the pushes below is the byte order in the file.** It is
/// `stores.Metadata`'s Go declaration order, not alphabetical, and it is pinned by
/// `emits_fields_in_the_declaration_order_go_yaml_uses`. Do not sort it.
#[must_use]
pub fn to_tree(m: &Metadata) -> Value {
    let mut items: Vec<Item> = Vec::new();

    if let Some(t) = m.shamir_threshold {
        items.push(pair("shamir_threshold", plain(&t.to_string())));
    }
    // `key_groups` is not emitted: a file using them is refused before this point
    // rather than round-tripped through a representation we do not model.
    for (provider, field, id_field) in PROVIDER_TABLE {
        // The table's age entry is last, matching Go's field order where `age`
        // follows the cloud providers — so iterate the table, not the key list.
        if *provider == KeyProvider::Age {
            continue;
        }
        push_provider(&mut items, m, *provider, field, id_field);
    }
    push_provider(&mut items, m, KeyProvider::Age, "age", "recipient");

    // `lastmodified` is a timestamp, so go-yaml quotes it. `Scalar::new` reaches
    // the same verdict through the resolver test rather than by special-casing
    // this field.
    items.push(pair(
        "lastmodified",
        Value::Scalar(Scalar::new(&m.lastmodified)),
    ));
    items.push(pair("mac", plain(&m.mac)));

    for (field, value) in [
        ("unencrypted_suffix", &m.unencrypted_suffix),
        ("encrypted_suffix", &m.encrypted_suffix),
        ("unencrypted_regex", &m.unencrypted_regex),
        ("encrypted_regex", &m.encrypted_regex),
        ("unencrypted_comment_regex", &m.unencrypted_comment_regex),
        ("encrypted_comment_regex", &m.encrypted_comment_regex),
    ] {
        if let Some(v) = value.as_deref().filter(|v| !v.is_empty()) {
            items.push(pair(field, plain(v)));
        }
    }
    if m.mac_only_encrypted {
        items.push(pair("mac_only_encrypted", plain("true")));
    }
    items.push(pair("version", plain(&m.version)));

    Value::Mapping(items)
}

fn push_provider(
    items: &mut Vec<Item>,
    m: &Metadata,
    provider: KeyProvider,
    field: &str,
    id_field: &str,
) {
    let keys = m.keys_for(provider);
    if keys.is_empty() {
        // `omitempty` on every provider array at the top level.
        return;
    }
    let entries = keys
        .into_iter()
        .map(|k| {
            let mut fields: Vec<Item> = Vec::new();
            // Field order inside a key record follows the Go struct too: the
            // cloud providers put `created_at` before `enc`, age has neither.
            fields.push(pair(id_field, plain(k.recipient())));
            if let Some(ts) = k.created_at() {
                fields.push(pair("created_at", plain(ts)));
            }
            // The wrapped key is a multi-line armored blob for age, and go-yaml
            // renders any newline-bearing string as a literal block.
            let enc = if k.enc().contains('\n') {
                Value::Scalar(Scalar::literal(k.enc()))
            } else {
                plain(k.enc())
            };
            fields.push(pair("enc", enc));
            suminuri_yaml::Entry::Value(Value::Mapping(fields))
        })
        .collect();
    items.push(pair(field, Value::Sequence(entries)));
}

fn pair(key: &str, value: Value) -> Item {
    Item::Pair {
        key: key.to_string(),
        value,
    }
}

/// A scalar emitted plain. Used where sops emits plain and the value is known not
/// to need quoting — a MAC, a recipient, a version string.
fn plain(v: &str) -> Value {
    Value::Scalar(Scalar::parsed(v, ScalarStyle::Plain))
}

#[cfg(test)]
mod tests {
    use super::*;
    use suminuri_yaml::parse;

    /// A real `sops:` block, lifted from a fixture upstream sops wrote.
    const REAL: &str = "\
sops:
    age:
        - recipient: age1jpfgn0cm8su4dt3a2c0928cyvhquvx0ayyssnctk5nwjdnpv85vsqssjrh
          enc: |
            -----BEGIN AGE ENCRYPTED FILE-----
            YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+
            -----END AGE ENCRYPTED FILE-----
    lastmodified: \"2026-08-18T00:00:00Z\"
    mac: ENC[AES256_GCM,data:abc,iv:def,tag:ghi,type:str]
    unencrypted_suffix: _unencrypted
    version: 3.12.1
";

    fn real_block() -> Value {
        parse(REAL)
            .expect("parse")
            .root()
            .and_then(|r| r.get("sops"))
            .cloned()
            .expect("sops key")
    }

    #[test]
    fn reads_a_real_block() {
        let m = from_tree(&real_block()).expect("from_tree");
        assert_eq!(m.lastmodified, "2026-08-18T00:00:00Z");
        assert_eq!(m.version, "3.12.1");
        assert_eq!(m.unencrypted_suffix.as_deref(), Some("_unencrypted"));
        assert!(!m.mac_only_encrypted);
        assert_eq!(m.age_keys().len(), 1);
        assert!(
            m.age_keys()[0]
                .enc
                .starts_with("-----BEGIN AGE ENCRYPTED FILE-----")
        );
        assert!(m.unimplemented_providers().is_empty());
    }

    /// The whole reason `to_tree` is hand-written: this is the byte order, and it
    /// is not alphabetical (`mac` before `unencrypted_suffix` before `version`,
    /// with the provider arrays first).
    #[test]
    fn emits_fields_in_the_declaration_order_go_yaml_uses() {
        let m = from_tree(&real_block()).expect("from_tree");
        let Value::Mapping(items) = to_tree(&m) else {
            panic!("mapping")
        };
        let keys: Vec<&str> = items
            .iter()
            .filter_map(|i| match i {
                Item::Pair { key, .. } => Some(key.as_str()),
                Item::Comment(_) => None,
            })
            .collect();
        assert_eq!(
            keys,
            vec![
                "age",
                "lastmodified",
                "mac",
                "unencrypted_suffix",
                "version"
            ]
        );
    }

    /// Read then write must reproduce the original block byte for byte. This is
    /// the metadata half of the file-level parity claim.
    #[test]
    fn the_block_round_trips_byte_exactly() {
        let m = from_tree(&real_block()).expect("from_tree");
        let doc = suminuri_yaml::Document::single(Value::Mapping(vec![pair("sops", to_tree(&m))]));
        let out = suminuri_yaml::emit(&doc, suminuri_yaml::EmitOptions::default()).expect("emit");
        assert_eq!(out, REAL);
    }

    #[test]
    fn a_missing_metadata_block_is_named() {
        let v = Value::Mapping(vec![pair("k", plain("v"))]);
        // `lastmodified` is the first required field checked.
        assert_eq!(
            from_tree(&v),
            Err(MetaError::MissingField {
                field: "lastmodified"
            })
        );
        assert_eq!(
            from_tree(&plain("scalar")),
            Err(MetaError::MetadataNotAMapping)
        );
    }

    #[test]
    fn a_key_entry_missing_its_enc_is_named_not_skipped() {
        let src = "\
sops:
    age:
        - recipient: age1abc
    lastmodified: \"2026-08-18T00:00:00Z\"
    mac: m
    version: 3.12.1
";
        let block = parse(src)
            .expect("parse")
            .root()
            .and_then(|r| r.get("sops"))
            .cloned()
            .unwrap();
        assert_eq!(
            from_tree(&block),
            Err(MetaError::MalformedKey {
                provider: "age",
                index: 0,
                field: "enc"
            })
        );
    }

    /// A provider we cannot unwrap must survive the round-trip, or aliasing over
    /// sops would strip a recipient's access on the first write.
    #[test]
    fn an_unimplemented_providers_keys_survive_a_round_trip() {
        let src = "\
sops:
    kms:
        - arn: arn:aws:kms:us-east-2:1:key/abc
          created_at: \"2026-01-01T00:00:00Z\"
          enc: CiAsomething
    age:
        - recipient: age1abc
          enc: armored
    lastmodified: \"2026-08-18T00:00:00Z\"
    mac: m
    version: 3.12.1
";
        let block = parse(src)
            .expect("parse")
            .root()
            .and_then(|r| r.get("sops"))
            .cloned()
            .unwrap();
        let m = from_tree(&block).expect("from_tree");
        assert_eq!(
            m.unimplemented_providers(),
            vec![suminuri_wire::KeyProvider::AwsKms]
        );

        let back = to_tree(&m);
        // kms comes before age, matching the Go struct order.
        let Value::Mapping(items) = &back else {
            panic!("mapping")
        };
        let keys: Vec<&str> = items
            .iter()
            .filter_map(|i| match i {
                Item::Pair { key, .. } => Some(key.as_str()),
                Item::Comment(_) => None,
            })
            .collect();
        assert_eq!(keys, vec!["kms", "age", "lastmodified", "mac", "version"]);
        // and the ARN plus its created_at are intact
        let kms = back.get("kms").expect("kms array");
        let Value::Sequence(entries) = kms else {
            panic!("sequence")
        };
        let suminuri_yaml::Entry::Value(first) = &entries[0] else {
            panic!("value")
        };
        assert_eq!(
            first.get("arn").and_then(Value::as_str),
            Some("arn:aws:kms:us-east-2:1:key/abc")
        );
        assert_eq!(
            first.get("created_at").and_then(Value::as_str),
            Some("2026-01-01T00:00:00Z")
        );
        assert_eq!(
            first.get("enc").and_then(Value::as_str),
            Some("CiAsomething")
        );
    }

    #[test]
    fn mac_only_encrypted_round_trips() {
        let src = "\
sops:
    age:
        - recipient: age1abc
          enc: armored
    lastmodified: \"2026-08-18T00:00:00Z\"
    mac: m
    mac_only_encrypted: true
    version: 3.12.1
";
        let block = parse(src)
            .expect("parse")
            .root()
            .and_then(|r| r.get("sops"))
            .cloned()
            .unwrap();
        let m = from_tree(&block).expect("from_tree");
        assert!(m.mac_only_encrypted);
        assert!(to_tree(&m).get("mac_only_encrypted").is_some());
    }
}
