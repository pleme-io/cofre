//! `.sops.yaml` — `creation_rules`, and the discovery walk that finds them.
//!
//! Only the part that decides **which recipients a newly-encrypted file gets**.
//! That is the whole of what the fleet uses: three `path_regex` rules, age-only,
//! no `key_groups`, no `destination_rules`, no `stores` block.
//!
//! # First match wins, and the order is the file's
//!
//! sops walks `creation_rules` top to bottom and takes the first whose
//! `path_regex` matches, treating a rule with no `path_regex` as a catch-all. So
//! rule order is semantic, which is another reason the tree model preserves it.
//!
//! # What is refused rather than approximated
//!
//! A rule carrying `key_groups`, or a provider this build cannot wrap, is a named
//! refusal. The alternative — encrypting to the age recipients and quietly
//! dropping the PGP ones — hands the operator a file that looks fine and that half
//! their team cannot open.

use crate::env::Environment;
use suminuri_yaml::{Entry, Value};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("{path}: {reason}")]
    Unparseable { path: String, reason: String },

    #[error("{path}: `creation_rules` is missing or is not a list")]
    NoCreationRules { path: String },

    #[error(
        "{path}: creation_rules[{index}] uses `key_groups`, which this build does not implement; refusing rather than encrypting to a subset of the intended recipients"
    )]
    KeyGroupsUnsupported { path: String, index: usize },

    #[error(
        "{path}: creation_rules[{index}] names {providers}, which this build cannot wrap; refusing rather than silently dropping those recipients"
    )]
    UnsupportedProviders {
        path: String,
        index: usize,
        providers: String,
    },

    #[error(
        "no creation_rule in {path} matches `{file}`, and no recipients were given on the command line"
    )]
    NoMatchingRule { path: String, file: String },

    #[error(
        "no .sops.yaml found from {from} upward, and no recipients were given on the command line"
    )]
    NoConfig { from: String },
}

/// One `creation_rules` entry, reduced to what we act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreationRule {
    /// `None` is a catch-all, which is how sops treats a rule with no regex.
    pub path_regex: Option<String>,
    /// Comma-separated age recipients, as written in the file.
    pub age: Vec<String>,
    pub unencrypted_suffix: Option<String>,
    pub encrypted_suffix: Option<String>,
    pub unencrypted_regex: Option<String>,
    pub encrypted_regex: Option<String>,
    pub mac_only_encrypted: bool,
}

/// A parsed `.sops.yaml`.
#[derive(Debug, Clone)]
pub struct SopsConfig {
    pub path: String,
    pub rules: Vec<CreationRule>,
}

impl SopsConfig {
    /// Find and parse the nearest `.sops.yaml`, walking up from `start`.
    ///
    /// `$SOPS_CONFIG` short-circuits the walk entirely, matching `--config`'s
    /// documented "sops will not search for the config file recursively".
    pub fn discover(
        env: &dyn Environment,
        start: &std::path::Path,
    ) -> Result<Option<Self>, ConfigError> {
        if let Some(explicit) = env.var("SOPS_CONFIG") {
            let src = env
                .read_to_string(std::path::Path::new(&explicit))
                .map_err(|e| ConfigError::Unparseable {
                    path: explicit.clone(),
                    reason: e.to_string(),
                })?;
            return Ok(Some(Self::parse(&explicit, &src)?));
        }
        let mut dir = if start.is_absolute() {
            start.parent().map(std::path::Path::to_path_buf)
        } else {
            Some(std::path::PathBuf::from("."))
        };
        while let Some(d) = dir {
            let candidate = d.join(".sops.yaml");
            if env.exists(&candidate) {
                let src = env
                    .read_to_string(&candidate)
                    .map_err(|e| ConfigError::Unparseable {
                        path: candidate.display().to_string(),
                        reason: e.to_string(),
                    })?;
                return Ok(Some(Self::parse(&candidate.display().to_string(), &src)?));
            }
            dir = d.parent().map(std::path::Path::to_path_buf);
        }
        Ok(None)
    }

    /// Parse a config's text.
    pub fn parse(path: &str, src: &str) -> Result<Self, ConfigError> {
        // `.sops.yaml` is the one file in this whole tool that is *expected* to be
        // full of comments — the operator's own `.sops.yaml` is mostly a 90-line
        // explanation of the fleet secrets model. The YAML layer refuses comments
        // to protect a *round-trip*, and there is no round-trip here: this file is
        // read and never written. So comments are stripped first, which is a
        // narrower thing than supporting them.
        let stripped = strip_comments(src);
        let doc = suminuri_yaml::parse(&stripped).map_err(|e| ConfigError::Unparseable {
            path: path.to_string(),
            reason: e.to_string(),
        })?;
        let root = doc.root().ok_or_else(|| ConfigError::Unparseable {
            path: path.to_string(),
            reason: "expected a single YAML document".into(),
        })?;
        let Some(Value::Sequence(entries)) = root.get("creation_rules") else {
            return Err(ConfigError::NoCreationRules {
                path: path.to_string(),
            });
        };

        let mut rules = Vec::new();
        for (index, entry) in entries.iter().enumerate() {
            let Entry::Value(v) = entry else { continue };
            if v.get("key_groups").is_some() {
                return Err(ConfigError::KeyGroupsUnsupported {
                    path: path.to_string(),
                    index,
                });
            }
            let unsupported: Vec<&str> = [
                "pgp",
                "kms",
                "gcp_kms",
                "hckms",
                "azure_keyvault",
                "hc_vault_transit",
            ]
            .into_iter()
            .filter(|k| v.get(k).is_some())
            .collect();
            if !unsupported.is_empty() {
                return Err(ConfigError::UnsupportedProviders {
                    path: path.to_string(),
                    index,
                    providers: unsupported.join(", "),
                });
            }
            let s = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);
            rules.push(CreationRule {
                path_regex: s("path_regex"),
                // sops accepts a comma-separated list in one scalar, which is how
                // the operator's own config writes three recipients on one line.
                age: s("age")
                    .map(|a| {
                        a.split(',')
                            .map(str::trim)
                            .filter(|p| !p.is_empty())
                            .map(str::to_string)
                            .collect()
                    })
                    .unwrap_or_default(),
                unencrypted_suffix: s("unencrypted_suffix"),
                encrypted_suffix: s("encrypted_suffix"),
                unencrypted_regex: s("unencrypted_regex"),
                encrypted_regex: s("encrypted_regex"),
                mac_only_encrypted: s("mac_only_encrypted").as_deref() == Some("true"),
            });
        }
        Ok(Self {
            path: path.to_string(),
            rules,
        })
    }

    /// The first rule whose `path_regex` matches `file`.
    ///
    /// The regex is matched **unanchored** against the path as given, which is
    /// what Go's `regexp.MatchString` does — so a rule of `^secrets\.yaml$` only
    /// matches a bare relative path, exactly as it does under sops. That is why
    /// the operator's config works when run from the repo root and would not from
    /// elsewhere; reproducing the quirk keeps both tools agreeing.
    #[must_use]
    pub fn rule_for(&self, file: &str) -> Option<&CreationRule> {
        self.rules.iter().find(|r| match &r.path_regex {
            None => true,
            Some(re) => regex_matches(re, file),
        })
    }
}

/// Unanchored regex match, or `false` on a pattern that does not compile.
///
/// A non-compiling `path_regex` matching nothing is upstream's behaviour
/// (`regexp.MatchString`'s error is discarded at the call site), and the
/// consequence — falling through to the next rule — is at least a *visible*
/// failure: the file ends up with the wrong recipients or with none, rather than
/// being silently encrypted to a partial set.
fn regex_matches(pattern: &str, text: &str) -> bool {
    // `suminuri-wire` already depends on `regex` for the selectors, so this is not
    // a new dependency; it is the same engine, which matters because both are
    // reproducing Go RE2 semantics.
    suminuri_wire::regex_is_match(pattern, text)
}

/// Remove YAML comments, tracking quotes and block scalars so a `#` inside a
/// value survives.
///
/// Shares its rules with `suminuri_yaml`'s comment *detector* but does the
/// opposite thing with the answer — there it refuses, here it strips, because this
/// file is read-only.
fn strip_comments(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut block_indent: Option<usize> = None;
    for raw in src.lines() {
        let indent = raw.len() - raw.trim_start().len();
        let trimmed = raw.trim_start();

        if let Some(open_at) = block_indent {
            if trimmed.is_empty() || indent > open_at {
                out.push_str(raw);
                out.push('\n');
                continue;
            }
            block_indent = None;
        }
        if trimmed.starts_with('#') {
            continue;
        }
        let kept = match unquoted_hash(raw) {
            Some(col) if col > 0 && raw.as_bytes()[col - 1].is_ascii_whitespace() => {
                raw[..col].trim_end()
            }
            _ => raw,
        };
        if kept.trim().is_empty() && !raw.trim().is_empty() {
            // The line was only a comment after leading whitespace.
            continue;
        }
        if let Some(after) = kept.rsplit(':').next() {
            let a = after.trim();
            if a.starts_with('|') || a.starts_with('>') {
                block_indent = Some(indent);
            }
        }
        out.push_str(kept);
        out.push('\n');
    }
    out
}

fn unquoted_hash(line: &str) -> Option<usize> {
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;
    for (i, c) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match c {
            '\\' if in_double => escaped = true,
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            '#' if !in_single && !in_double => return Some(i),
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::MockEnvironment;

    /// The operator's real `.sops.yaml`, reduced to its structure. The recipients
    /// are public age keys, which is what a recipient is.
    const FLEET: &str = r#"
creation_rules:
  # ── The fleet secrets model ──────────────────────────────────────────
  #
  # Two kinds of file, two access boundaries. See docs/arch/secrets-strategy.md.
  - path_regex: ^secrets\.yaml$
    age: age1q3tep4cc4d89y0ajd9ywafmarq69202z3za48rhcdra0ya579ews56awfd,age1k5suekrkeq5twak0esc2h3qjkehgw0v0qn870zxsr770sejg8c5sp4zgw5,age1qev37zckl00p2vdxf9vvp93k09nlevtsps90zzwnfwvsg3hq6qaqnzcpy7
  - path_regex: ^users/drzzln/secrets\.yaml$
    age: age1q3tep4cc4d89y0ajd9ywafmarq69202z3za48rhcdra0ya579ews56awfd
  - path_regex: ^users/gabi/secrets\.yaml$
    # GABI IS THE SOLE RECIPIENT — her own key, her own secrets.
    age: age1qev37zckl00p2vdxf9vvp93k09nlevtsps90zzwnfwvsg3hq6qaqnzcpy7
"#;

    #[test]
    fn parses_the_fleets_own_config_comments_and_all() {
        let cfg = SopsConfig::parse(".sops.yaml", FLEET).expect("parse");
        assert_eq!(cfg.rules.len(), 3);
        assert_eq!(
            cfg.rules[0].age.len(),
            3,
            "a comma-separated recipient list"
        );
        assert_eq!(cfg.rules[1].age.len(), 1);
        assert_eq!(cfg.rules[2].age.len(), 1);
    }

    /// The comment on the third rule sits between `path_regex` and `age`, which is
    /// where a naive stripper breaks the mapping.
    #[test]
    fn a_comment_between_two_keys_does_not_break_the_rule() {
        let cfg = SopsConfig::parse(".sops.yaml", FLEET).expect("parse");
        assert_eq!(
            cfg.rules[2].age,
            vec!["age1qev37zckl00p2vdxf9vvp93k09nlevtsps90zzwnfwvsg3hq6qaqnzcpy7"]
        );
    }

    #[test]
    fn first_matching_rule_wins() {
        let cfg = SopsConfig::parse(".sops.yaml", FLEET).expect("parse");
        assert_eq!(cfg.rule_for("secrets.yaml").expect("match").age.len(), 3);
        assert_eq!(
            cfg.rule_for("users/drzzln/secrets.yaml")
                .expect("match")
                .age
                .len(),
            1
        );
        assert!(
            cfg.rule_for("some/other/file.yaml").is_none(),
            "no catch-all in this config"
        );
    }

    #[test]
    fn a_rule_with_no_path_regex_is_a_catch_all() {
        let cfg = SopsConfig::parse(
            ".sops.yaml",
            "creation_rules:\n  - path_regex: ^only\\.yaml$\n    age: age1aaa\n  - age: age1fallback\n",
        )
        .expect("parse");
        assert_eq!(cfg.rule_for("only.yaml").expect("m").age, vec!["age1aaa"]);
        assert_eq!(
            cfg.rule_for("anything-else").expect("m").age,
            vec!["age1fallback"]
        );
    }

    /// Unanchored, like Go's `regexp.MatchString`. `secrets\.yaml` without anchors
    /// matches a nested path too — the operator's rules are anchored precisely to
    /// avoid that, and reproducing the looseness keeps both tools agreeing.
    #[test]
    fn path_regex_is_unanchored_like_go() {
        let cfg = SopsConfig::parse(
            ".sops.yaml",
            "creation_rules:\n  - path_regex: secrets\\.yaml\n    age: age1aaa\n",
        )
        .expect("parse");
        assert!(cfg.rule_for("deep/nested/secrets.yaml").is_some());
        let anchored = SopsConfig::parse(
            ".sops.yaml",
            "creation_rules:\n  - path_regex: ^secrets\\.yaml$\n    age: age1aaa\n",
        )
        .expect("parse");
        assert!(anchored.rule_for("deep/nested/secrets.yaml").is_none());
        assert!(anchored.rule_for("secrets.yaml").is_some());
    }

    #[test]
    fn a_key_group_rule_is_refused_by_name() {
        let err = SopsConfig::parse(
            ".sops.yaml",
            "creation_rules:\n  - key_groups:\n      - age:\n          - age1aaa\n",
        )
        .expect_err("must refuse");
        assert!(
            matches!(err, ConfigError::KeyGroupsUnsupported { index: 0, .. }),
            "got {err}"
        );
    }

    /// The failure mode this refusal exists for: encrypting to the age half and
    /// dropping the PGP half hands the operator a file half their team cannot open.
    #[test]
    fn a_rule_naming_an_unsupported_provider_is_refused_not_partially_honoured() {
        let err = SopsConfig::parse(
            ".sops.yaml",
            "creation_rules:\n  - age: age1aaa\n    pgp: DEADBEEF\n",
        )
        .expect_err("must refuse");
        assert!(
            matches!(err, ConfigError::UnsupportedProviders { .. }),
            "got {err}"
        );
        assert!(err.to_string().contains("pgp"), "{err}");
    }

    #[test]
    fn a_config_without_creation_rules_is_named() {
        let err = SopsConfig::parse(".sops.yaml", "stores:\n  yaml:\n    indent: 2\n")
            .expect_err("must refuse");
        assert!(
            matches!(err, ConfigError::NoCreationRules { .. }),
            "got {err}"
        );
    }

    #[test]
    fn selector_fields_are_carried_through() {
        let cfg = SopsConfig::parse(
            ".sops.yaml",
            "creation_rules:\n  - age: age1aaa\n    unencrypted_suffix: _plain\n    mac_only_encrypted: true\n",
        )
        .expect("parse");
        let r = cfg.rule_for("f.yaml").expect("match");
        assert_eq!(r.unencrypted_suffix.as_deref(), Some("_plain"));
        assert!(r.mac_only_encrypted);
    }

    #[test]
    fn discovery_walks_up_to_the_nearest_config() {
        let env = MockEnvironment::new()
            .with_file("/repo/.sops.yaml", "creation_rules:\n  - age: age1root\n")
            .with_file("/repo/deep/dir/f.yaml", "k: v\n");
        let cfg = SopsConfig::discover(&env, std::path::Path::new("/repo/deep/dir/f.yaml"))
            .expect("discover")
            .expect("found");
        assert_eq!(cfg.path, "/repo/.sops.yaml");
        assert_eq!(cfg.rules[0].age, vec!["age1root"]);
    }

    #[test]
    fn a_nearer_config_wins_the_walk() {
        let env = MockEnvironment::new()
            .with_file("/repo/.sops.yaml", "creation_rules:\n  - age: age1root\n")
            .with_file(
                "/repo/deep/.sops.yaml",
                "creation_rules:\n  - age: age1deep\n",
            );
        let cfg = SopsConfig::discover(&env, std::path::Path::new("/repo/deep/dir/f.yaml"))
            .expect("discover")
            .expect("found");
        assert_eq!(cfg.rules[0].age, vec!["age1deep"]);
    }

    /// `$SOPS_CONFIG` must skip the walk entirely — `--config`'s documented
    /// behaviour is "sops will not search for the config file recursively".
    #[test]
    fn sops_config_env_short_circuits_the_walk() {
        let env = MockEnvironment::new()
            .with_var("SOPS_CONFIG", "/elsewhere/custom.yaml")
            .with_file(
                "/elsewhere/custom.yaml",
                "creation_rules:\n  - age: age1custom\n",
            )
            .with_file("/repo/.sops.yaml", "creation_rules:\n  - age: age1root\n");
        let cfg = SopsConfig::discover(&env, std::path::Path::new("/repo/f.yaml"))
            .expect("discover")
            .expect("found");
        assert_eq!(cfg.rules[0].age, vec!["age1custom"]);
    }

    #[test]
    fn no_config_anywhere_is_none_not_an_error() {
        let env = MockEnvironment::new();
        assert!(
            SopsConfig::discover(&env, std::path::Path::new("/repo/f.yaml"))
                .expect("discover")
                .is_none()
        );
    }

    #[test]
    fn a_hash_inside_a_recipient_list_is_not_stripped() {
        // Contrived, but the stripper must not cut on a `#` with no leading space.
        let cfg = SopsConfig::parse(
            ".sops.yaml",
            "creation_rules:\n  - age: age1aaa#notacomment\n",
        )
        .expect("parse");
        assert_eq!(cfg.rules[0].age, vec!["age1aaa#notacomment"]);
    }
}
