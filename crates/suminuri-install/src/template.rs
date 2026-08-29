//! Rendering a template body from decrypted values.
//!
//! ── ★ WHAT A TEMPLATE IS ON A REAL NODE ────────────────────────────────
//!
//! plo carries four. Their `content` is a whole file — cloudflared's tunnel
//! credentials are one — with `<SOPS:<hash>:PLACEHOLDER>` markers standing in
//! for secrets. `placeholderBySecretName` maps each secret's name to the
//! marker that represents it, so rendering is a substitution over that table.
//!
//! ── ★ AN UNRESOLVED PLACEHOLDER IS AN ERROR, NEVER A LITERAL ───────────
//!
//! This is the whole reason the module has a typed error at all. If a marker
//! survives into the rendered file, the file is still WRITTEN, still owned and
//! moded correctly, and still looks exactly like a credential — and the
//! service reading it sends `<SOPS:9b4b…:PLACEHOLDER>` as its tunnel secret.
//! Every surface reports success. Refusing is the only outcome that surfaces
//! the fault.

use std::collections::BTreeMap;

/// Why a template could not be rendered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TemplateError {
    /// A marker remained after every known substitution was applied.
    ///
    /// ★ Carries the template and how many markers survived, because the
    /// useful question is "which template, and is it one placeholder or all of
    /// them" — one suggests a renamed secret, all suggests an empty
    /// substitution table.
    UnresolvedPlaceholders { template: String, remaining: usize },
    /// A secret the substitution table names had no plaintext.
    MissingValue { template: String, secret: String },
}

impl std::fmt::Display for TemplateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnresolvedPlaceholders { template, remaining } => write!(
                f,
                "template {template}: {remaining} placeholder(s) unresolved — refusing, \
                 because a rendered marker would be written as if it were the credential"
            ),
            Self::MissingValue { template, secret } => {
                write!(f, "template {template}: no plaintext for {secret}")
            }
        }
    }
}

/// The marker prefix sops-nix emits.
const MARKER_PREFIX: &str = "<SOPS:";

/// Render `content`, substituting each secret's plaintext for its placeholder.
///
/// `values` maps secret name -> plaintext; `placeholders` maps secret name ->
/// the marker standing for it.
///
/// # Errors
/// [`TemplateError`] if a named secret has no value, or if any marker survives.
pub fn render(
    template_name: &str,
    content: &str,
    placeholders: &BTreeMap<String, String>,
    values: &BTreeMap<String, Vec<u8>>,
) -> Result<String, TemplateError> {
    let mut out = content.to_owned();
    for (secret, marker) in placeholders {
        // ★ Only substitute markers this body actually contains. The table is
        // node-wide -- plo's lists all 27 secrets -- while a template uses a
        // handful, and treating an unused entry as missing would fail every
        // template for secrets it never referenced.
        if !out.contains(marker.as_str()) {
            continue;
        }
        let value = values
            .get(secret)
            .ok_or_else(|| TemplateError::MissingValue {
                template: template_name.to_owned(),
                secret: secret.clone(),
            })?;
        out = out.replace(marker.as_str(), &String::from_utf8_lossy(value));
    }

    // ★ THE SWEEP. Substitution succeeding for every KNOWN placeholder does
    // not mean the body is clean: a marker for a secret dropped from the
    // manifest is not in the table at all, so nothing above would touch it.
    let remaining = out.matches(MARKER_PREFIX).count();
    if remaining > 0 {
        return Err(TemplateError::UnresolvedPlaceholders {
            template: template_name.to_owned(),
            remaining,
        });
    }
    Ok(out)
}

/// Which secrets a template body references.
///
/// ★ Used to order work: a template can only be rendered once every secret it
/// names has been decrypted, so this is what makes "templates after entries"
/// a derived fact rather than a convention.
#[must_use]
pub fn referenced(content: &str, placeholders: &BTreeMap<String, String>) -> Vec<String> {
    placeholders
        .iter()
        .filter(|(_, marker)| content.contains(marker.as_str()))
        .map(|(secret, _)| secret.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table() -> BTreeMap<String, String> {
        [
            ("tunnel/id".to_string(), "<SOPS:aaa:PLACEHOLDER>".to_string()),
            ("tunnel/sec".to_string(), "<SOPS:bbb:PLACEHOLDER>".to_string()),
            ("unrelated".to_string(), "<SOPS:ccc:PLACEHOLDER>".to_string()),
        ]
        .into_iter()
        .collect()
    }

    fn values() -> BTreeMap<String, Vec<u8>> {
        [
            ("tunnel/id".to_string(), b"ID".to_vec()),
            ("tunnel/sec".to_string(), b"SEC".to_vec()),
        ]
        .into_iter()
        .collect()
    }

    #[test]
    fn a_body_is_rendered_from_its_referenced_secrets() {
        let body = r#"{"TunnelID":"<SOPS:aaa:PLACEHOLDER>","TunnelSecret":"<SOPS:bbb:PLACEHOLDER>"}"#;
        let out = render("cloudflared", body, &table(), &values()).expect("render");
        assert_eq!(out, r#"{"TunnelID":"ID","TunnelSecret":"SEC"}"#);
    }

    #[test]
    fn an_unknown_marker_is_refused_rather_than_written_through() {
        // THE test. A surviving marker would be written as if it WERE the
        // credential -- correct mode, correct owner, and the service sends
        // "<SOPS:...:PLACEHOLDER>" as its tunnel secret while every surface
        // reports success.
        let body = r#"{"a":"<SOPS:aaa:PLACEHOLDER>","b":"<SOPS:zzz:PLACEHOLDER>"}"#;
        assert_eq!(
            render("t", body, &table(), &values()),
            Err(TemplateError::UnresolvedPlaceholders { template: "t".into(), remaining: 1 })
        );
    }

    #[test]
    fn a_table_entry_the_body_never_uses_is_not_a_missing_value() {
        // The table is node-wide -- plo's lists all 27 secrets -- while a
        // template uses a handful. Treating an unused entry as missing would
        // fail every template for secrets it never referenced.
        let body = r#"{"a":"<SOPS:aaa:PLACEHOLDER>"}"#;
        // `unrelated` is in the table and has NO value, and that must not matter.
        assert!(render("t", body, &table(), &values()).is_ok());
    }

    #[test]
    fn a_referenced_secret_with_no_plaintext_is_named() {
        let mut t = table();
        t.insert("absent".into(), "<SOPS:ddd:PLACEHOLDER>".into());
        let body = r#"{"x":"<SOPS:ddd:PLACEHOLDER>"}"#;
        assert_eq!(
            render("t", body, &t, &values()),
            Err(TemplateError::MissingValue { template: "t".into(), secret: "absent".into() })
        );
    }

    #[test]
    fn a_body_with_no_markers_renders_unchanged() {
        let body = "plain content\n";
        assert_eq!(render("t", body, &table(), &values()).expect("render"), body);
    }

    #[test]
    fn the_same_marker_twice_is_substituted_both_times() {
        // `replace` handles this, but a hand-rolled find-first would not, and
        // the failure would be a half-rendered credential.
        let body = "<SOPS:aaa:PLACEHOLDER>-<SOPS:aaa:PLACEHOLDER>";
        assert_eq!(render("t", body, &table(), &values()).expect("render"), "ID-ID");
    }

    #[test]
    fn referenced_lists_only_what_the_body_actually_names() {
        let body = r#"{"a":"<SOPS:aaa:PLACEHOLDER>"}"#;
        assert_eq!(referenced(body, &table()), vec!["tunnel/id".to_string()]);
    }
}
