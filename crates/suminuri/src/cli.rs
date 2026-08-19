//! The sops-compatible argv surface, and the exit codes that go with it.
//!
//! # Why this is hand-parsed rather than clap-derived
//!
//! sops's grammar has three shapes clap fights:
//!
//! 1. **A bare file is a verb.** `sops secrets.yaml` means `edit`, so the
//!    positional-only form has to dispatch to a subcommand.
//! 2. **Legacy flags coexist with subcommands.** `-d`, `-e` and `-r` are top-level
//!    flags that *are* verbs, alongside `decrypt`, `encrypt`, `rotate`.
//! 3. **Flags must precede the filename** or they are silently ignored — sops's
//!    own help says so. Reproducing a quirk is a deliberate act; clap would
//!    "helpfully" accept the trailing form and the two tools would then disagree
//!    about what `sops file.yaml -d` means.
//!
//! Being aliased over `sops` means muscle memory is the spec. A parser that is
//! *better* than the original is a parser that behaves differently, and different
//! is the one thing an alias cannot be.
//!
//! # Unimplemented is a refusal, never a no-op
//!
//! Every verb and flag sops has appears here. The ones this build does not serve
//! exit non-zero with a message naming them. That is the whole safety argument for
//! the alias: a silently-ignored `--shamir-secret-sharing-threshold` would write a
//! file with the wrong protection and report success.

use std::path::PathBuf;

/// sops's exit codes, as far as they are observable from outside.
///
/// **200 is load-bearing.** It means "the file has not changed" after an edit, and
/// `cofre`'s own SOPS backend already branches on that exact value
/// (`crates/cofre/src/backends.rs`), so it is part of the contract rather than a
/// detail. Getting it wrong turns an idempotent no-op into a reported failure.
pub mod exit {
    pub const OK: i32 = 0;
    pub const GENERIC: i32 = 1;
    pub const FILE_HAS_NOT_CHANGED: i32 = 200;
}

/// What the operator asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verb {
    Edit,
    Decrypt,
    Encrypt,
    Rotate,
    UpdateKeys,
    FileStatus,
    /// `set <file> <path> <value>` — write one leaf without opening an editor.
    Set,
    /// `unset <file> <path>` — remove one leaf.
    Unset,
    Version,
    Help,
    /// A verb sops has that this build does not serve. Carries the name so the
    /// refusal can say which.
    Unimplemented(String),
}

/// A parsed command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invocation {
    pub verb: Verb,
    pub file: Option<PathBuf>,
    pub in_place: bool,
    pub output: Option<PathBuf>,
    pub ignore_mac: bool,
    pub indent: Option<usize>,
    /// `--age` / `-a`, split on commas.
    pub age_recipients: Vec<String>,
    pub extract: Option<String>,
    /// `set`/`unset`'s bracket path — the same syntax `--extract` takes, parsed by
    /// the same function. Three verbs now share one parser; a second copy of that
    /// grammar is how `["a"]["b"]` starts meaning two different things.
    pub path_expr: Option<String>,
    /// `set`'s value argument, as written on the command line (sops takes JSON).
    pub value_expr: Option<String>,
    pub input_type: Option<String>,
    pub output_type: Option<String>,
    pub mac_only_encrypted: bool,
    pub unencrypted_suffix: Option<String>,
    pub encrypted_suffix: Option<String>,
    pub unencrypted_regex: Option<String>,
    pub encrypted_regex: Option<String>,
    pub config: Option<PathBuf>,
    pub verbose: bool,
    /// Flags sops accepts that this build cannot honour. Non-empty means refuse.
    pub unsupported: Vec<String>,
    /// `yes` when the caller asked not to check for a new release. Reproduced
    /// because sops's own check *blocks on the network*, and a hung `sops` inside
    /// a nix build is a wedged rebuild rather than a slow one.
    pub disable_version_check: bool,
}

impl Default for Invocation {
    fn default() -> Self {
        Self {
            verb: Verb::Help,
            file: None,
            in_place: false,
            output: None,
            ignore_mac: false,
            indent: None,
            age_recipients: Vec::new(),
            extract: None,
            path_expr: None,
            value_expr: None,
            input_type: None,
            output_type: None,
            mac_only_encrypted: false,
            unencrypted_suffix: None,
            encrypted_suffix: None,
            unencrypted_regex: None,
            encrypted_regex: None,
            config: None,
            verbose: false,
            unsupported: Vec::new(),
            disable_version_check: false,
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ParseError {
    #[error("flag `{0}` needs a value")]
    MissingValue(String),
    #[error("`{0}` is not a number")]
    NotANumber(String),
    #[error("unknown flag `{0}`")]
    UnknownFlag(String),
    #[error("more than one file given: `{first}` and `{second}`")]
    TooManyFiles { first: String, second: String },
}

/// Flags sops has that this build cannot honour, and which therefore must be
/// refused rather than ignored.
///
/// Split by arity so the parser consumes the value too — a flag whose value was
/// left on the line would then be mistaken for the filename, which is precisely
/// the class of confusion this table exists to avoid.
const UNSUPPORTED_WITH_VALUE: &[&str] = &[
    "--kms",
    "-k",
    "--aws-profile",
    "--gcp-kms",
    "--hckms",
    "--azure-kv",
    "--hc-vault-transit",
    "--pgp",
    "-p",
    "--add-gcp-kms",
    "--rm-gcp-kms",
    "--add-hckms",
    "--rm-hckms",
    "--add-azure-kv",
    "--rm-azure-kv",
    "--add-kms",
    "--rm-kms",
    "--add-hc-vault-transit",
    "--rm-hc-vault-transit",
    "--add-pgp",
    "--rm-pgp",
    "--encryption-context",
    "--set",
    "--shamir-secret-sharing-threshold",
    "--unencrypted-comment-regex",
    "--encrypted-comment-regex",
    "--decryption-order",
    "--keyservice",
    "--filename-override",
    // `--add-age`/`--rm-age` are a rekey surface we have the pieces for but have
    // not wired; naming them beats a partial rekey.
    "--add-age",
    "--rm-age",
];

const UNSUPPORTED_FLAGS: &[&str] = &["--show-master-keys", "-s", "--enable-local-keyservice"];

/// Verbs sops has that this build does not serve.
///
/// `set` and `unset` LEFT this list on 2026-08-19, and the reason is worth keeping:
/// they were the only refused verbs the fleet actually *used*. Measured across the
/// nix repo (2755 files, denominator stated because a bare `grep -r` from the org
/// root reads zero and reports "no matches"): `set` appeared in 5 places — one live
/// caller (`tools/init-akeyless-dev.tlisp`, which invokes it and `die`s on failure)
/// and two operator-facing docs. The other six refused verbs appeared **nowhere**.
///
/// So aliasing `sops` to this binary broke exactly one real workflow, loudly. That
/// is the gap this closes, and the list below is now genuinely unused by the fleet
/// rather than merely unimplemented.
const UNSUPPORTED_VERBS: &[&str] = &[
    "groups",
    "exec-env",
    "exec-file",
    "publish",
    "keyservice",
    "completion",
];

/// Parse an argv (without the program name).
pub fn parse(args: &[String]) -> Result<Invocation, ParseError> {
    let mut inv = Invocation::default();
    let mut verb_from_subcommand: Option<Verb> = None;
    let mut verb_from_flag: Option<Verb> = None;
    let mut i = 0;

    // A leading non-flag token is a subcommand if it names one; otherwise it is
    // the file and the verb is `edit`.
    if let Some(first) = args.first() {
        if !first.starts_with('-') {
            verb_from_subcommand = match first.as_str() {
                "decrypt" => Some(Verb::Decrypt),
                "encrypt" => Some(Verb::Encrypt),
                "edit" => Some(Verb::Edit),
                "rotate" => Some(Verb::Rotate),
                "updatekeys" => Some(Verb::UpdateKeys),
                "filestatus" => Some(Verb::FileStatus),
                "set" => Some(Verb::Set),
                "unset" => Some(Verb::Unset),
                "help" | "h" => Some(Verb::Help),
                other if UNSUPPORTED_VERBS.contains(&other) => {
                    Some(Verb::Unimplemented(other.to_string()))
                }
                // Not a verb, so it is the file. Leave `i` at 0 so the loop picks
                // it up as a positional.
                _ => None,
            };
            // A verb we do not serve gets no further parsing. `exec-env f.yaml cmd
            // arg…` has trailing words that are neither flags nor the file, and
            // trying to classify them yields a confusing "too many files" instead
            // of the honest "this verb is not implemented". The run refuses either
            // way, so the parse should not editorialise.
            if let Some(Verb::Unimplemented(name)) = &verb_from_subcommand {
                return Ok(Invocation {
                    verb: Verb::Unimplemented(name.clone()),
                    ..Invocation::default()
                });
            }
            if verb_from_subcommand.is_some() {
                i = 1;
            }
        }
    }

    // `set` and `unset` are the only verbs with positionals beyond the file, so the
    // positional arm below has to know which shape it is filling. Read from the
    // SUBCOMMAND only: `sops -d f.yaml '["a"]' 'v'` is not a set, and treating a
    // stray third word as a value would write a secret the caller never asked to
    // write.
    let takes_path_args = matches!(verb_from_subcommand, Some(Verb::Set) | Some(Verb::Unset));

    while i < args.len() {
        let arg = &args[i];
        let mut take_value = |name: &str| -> Result<String, ParseError> {
            // Both `--flag value` and `--flag=value`.
            if let Some(eq) = arg.find('=') {
                return Ok(arg[eq + 1..].to_string());
            }
            i += 1;
            args.get(i)
                .cloned()
                .ok_or_else(|| ParseError::MissingValue(name.to_string()))
        };
        let bare = arg.split('=').next().unwrap_or(arg);

        match bare {
            "-d" | "--decrypt" => verb_from_flag = Some(Verb::Decrypt),
            "-e" | "--encrypt" => verb_from_flag = Some(Verb::Encrypt),
            "-r" | "--rotate" => verb_from_flag = Some(Verb::Rotate),
            "-v" | "--version" => verb_from_flag = Some(Verb::Version),
            "-h" | "--help" => verb_from_flag = Some(Verb::Help),

            "-i" | "--in-place" => inv.in_place = true,
            "--ignore-mac" => inv.ignore_mac = true,
            "--mac-only-encrypted" => inv.mac_only_encrypted = true,
            "--verbose" => inv.verbose = true,
            "--disable-version-check" => inv.disable_version_check = true,
            "--check-for-updates" => inv.disable_version_check = false,

            "--output" => inv.output = Some(PathBuf::from(take_value("--output")?)),
            "--extract" => inv.extract = Some(take_value("--extract")?),
            "--input-type" => inv.input_type = Some(take_value("--input-type")?),
            "--output-type" => inv.output_type = Some(take_value("--output-type")?),
            "--config" => inv.config = Some(PathBuf::from(take_value("--config")?)),
            "--unencrypted-suffix" => {
                inv.unencrypted_suffix = Some(take_value("--unencrypted-suffix")?)
            }
            "--encrypted-suffix" => inv.encrypted_suffix = Some(take_value("--encrypted-suffix")?),
            "--unencrypted-regex" => {
                inv.unencrypted_regex = Some(take_value("--unencrypted-regex")?)
            }
            "--encrypted-regex" => inv.encrypted_regex = Some(take_value("--encrypted-regex")?),
            "-a" | "--age" => {
                let v = take_value("--age")?;
                inv.age_recipients.extend(
                    v.split(',')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_string),
                );
            }
            "--indent" => {
                let v = take_value("--indent")?;
                inv.indent = Some(
                    v.parse::<usize>()
                        .map_err(|_| ParseError::NotANumber(v.clone()))?,
                );
            }

            other if UNSUPPORTED_WITH_VALUE.contains(&other) => {
                // Consume the value so it is not mistaken for the filename.
                let _ = take_value(other)?;
                inv.unsupported.push(other.to_string());
            }
            other if UNSUPPORTED_FLAGS.contains(&other) => {
                inv.unsupported.push(other.to_string());
            }

            other if other.starts_with('-') && other != "-" => {
                return Err(ParseError::UnknownFlag(other.to_string()));
            }

            // A positional: the file, then (for set/unset) the path and the value.
            positional => match (&inv.file, takes_path_args, &inv.path_expr) {
                (None, _, _) => inv.file = Some(PathBuf::from(positional)),
                (Some(_), true, None) => inv.path_expr = Some(positional.to_string()),
                (Some(_), true, Some(_)) if inv.value_expr.is_none() => {
                    inv.value_expr = Some(positional.to_string());
                }
                (Some(first), _, _) => {
                    return Err(ParseError::TooManyFiles {
                        first: first.display().to_string(),
                        second: positional.to_string(),
                    });
                }
            },
        }
        i += 1;
    }

    // Precedence: an explicit subcommand beats a legacy flag, and both beat the
    // bare-file default. `sops decrypt -e f` is contradictory; sops resolves it by
    // taking the subcommand, so we do too.
    inv.verb = match (verb_from_subcommand, verb_from_flag) {
        (Some(v), _) => v,
        (None, Some(v)) => v,
        (None, None) if inv.file.is_some() => Verb::Edit,
        (None, None) => Verb::Help,
    };
    Ok(inv)
}

/// The `--help` text.
///
/// Deliberately *not* a clone of sops's. An alias should be honest about which
/// binary is answering — an operator debugging a strange result needs to be able
/// to tell, and silently impersonating the help output is how a tool becomes
/// undiagnosable.
#[must_use]
pub fn help_text() -> String {
    let mut s = String::new();
    s.push_str(
        "suminuri (墨塗り) — a pleme-io-native, sops-wire-compatible encrypted-file tool\n\n",
    );
    s.push_str("This binary is wire-compatible with sops and can be aliased as `sops`.\n");
    s.push_str("It is NOT sops; when something behaves unexpectedly, that is worth knowing.\n\n");
    s.push_str("USAGE:\n");
    s.push_str("    suminuri [flags] <file>              edit (the bare form)\n");
    s.push_str("    suminuri decrypt [flags] <file>      decrypt to stdout\n");
    s.push_str("    suminuri encrypt [flags] <file>      encrypt to stdout\n");
    s.push_str("    suminuri edit [flags] <file>         decrypt, edit, re-encrypt in place\n");
    s.push_str("    suminuri rotate [flags] <file>       new data key, re-encrypt every value\n");
    s.push_str("    suminuri updatekeys <file>           re-wrap for the config's recipients\n");
    s.push_str("    suminuri filestatus <file>           report whether the file is encrypted\n");
    s.push_str(
        "    suminuri set <file> <path> <val>     write one leaf, e.g. '[\"db\"][\"handle\"]' '\"text\"'\n",
    );
    s.push_str("    suminuri unset <file> <path>         remove one leaf\n\n");
    s.push_str("FLAGS:\n");
    s.push_str("    -d, --decrypt            decrypt to stdout\n");
    s.push_str("    -e, --encrypt            encrypt to stdout\n");
    s.push_str("    -r, --rotate             rotate the data key\n");
    s.push_str("    -i, --in-place           write back to the same file\n");
    s.push_str("    -a, --age <recipients>   comma-separated age recipients\n");
    s.push_str("        --output <path>      write here instead of stdout\n");
    s.push_str("        --extract <path>     extract one key, e.g. '[\"db\"][\"password\"]'\n");
    s.push_str("        --indent <n>         YAML indent (default: the file's own)\n");
    s.push_str("        --ignore-mac         skip the integrity check (say why in the commit)\n");
    s.push_str("        --config <path>      use this .sops.yaml and do not search upward\n");
    s.push_str("    -v, --version            print the version\n");
    s.push_str("    -h, --help               this text\n\n");
    s.push_str("NOT IMPLEMENTED (refused, never silently ignored):\n");
    s.push_str("    PGP / AWS KMS / GCP KMS / HuaweiCloud KMS / Azure Key Vault / Vault transit\n");
    s.push_str("    key groups + Shamir secret sharing, key services, exec-env, exec-file,\n");
    s.push_str("    publish, groups, set, unset, shell completion\n\n");
    s.push_str("    A file using any of these is refused with a message naming it. Reach for\n");
    s.push_str("    upstream sops for those files; both read and write the same format.\n");
    s
}

/// The `--version` text.
#[must_use]
pub fn version_text() -> String {
    format!(
        "suminuri {} (墨塗り) — sops wire format {}\n",
        env!("CARGO_PKG_VERSION"),
        suminuri_wire::FORMAT_VERSION
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(args: &[&str]) -> Invocation {
        parse(&args.iter().map(|s| (*s).to_string()).collect::<Vec<_>>()).expect("parse")
    }

    /// `sops secrets.yaml` is an edit. The single most-typed invocation there is.
    #[test]
    fn a_bare_file_is_an_edit() {
        let inv = p(&["secrets.yaml"]);
        assert_eq!(inv.verb, Verb::Edit);
        assert_eq!(inv.file, Some(PathBuf::from("secrets.yaml")));
    }

    #[test]
    fn legacy_flags_are_verbs() {
        assert_eq!(p(&["-d", "f.yaml"]).verb, Verb::Decrypt);
        assert_eq!(p(&["--decrypt", "f.yaml"]).verb, Verb::Decrypt);
        assert_eq!(p(&["-e", "f.yaml"]).verb, Verb::Encrypt);
        assert_eq!(p(&["-r", "f.yaml"]).verb, Verb::Rotate);
    }

    #[test]
    fn subcommands_work_too() {
        assert_eq!(p(&["decrypt", "f.yaml"]).verb, Verb::Decrypt);
        assert_eq!(p(&["encrypt", "f.yaml"]).verb, Verb::Encrypt);
        assert_eq!(p(&["updatekeys", "f.yaml"]).verb, Verb::UpdateKeys);
        assert_eq!(p(&["filestatus", "f.yaml"]).verb, Verb::FileStatus);
        assert_eq!(p(&["rotate", "f.yaml"]).verb, Verb::Rotate);
    }

    #[test]
    fn a_subcommand_beats_a_contradicting_legacy_flag() {
        assert_eq!(p(&["decrypt", "-e", "f.yaml"]).verb, Verb::Decrypt);
    }

    #[test]
    fn no_arguments_is_help() {
        assert_eq!(p(&[]).verb, Verb::Help);
        assert_eq!(p(&["--help"]).verb, Verb::Help);
        assert_eq!(p(&["-v"]).verb, Verb::Version);
    }

    #[test]
    fn recipients_split_on_commas_and_accumulate() {
        let inv = p(&["-e", "-a", "age1aaa,age1bbb", "--age", "age1ccc", "f.yaml"]);
        assert_eq!(inv.age_recipients, vec!["age1aaa", "age1bbb", "age1ccc"]);
    }

    #[test]
    fn equals_form_is_accepted_for_values() {
        let inv = p(&[
            "-e",
            "--age=age1aaa",
            "--indent=2",
            "--output=/tmp/o.yaml",
            "f.yaml",
        ]);
        assert_eq!(inv.age_recipients, vec!["age1aaa"]);
        assert_eq!(inv.indent, Some(2));
        assert_eq!(inv.output, Some(PathBuf::from("/tmp/o.yaml")));
    }

    #[test]
    fn the_common_fleet_invocations_parse() {
        // `nix run .#sops-edit` shape
        assert_eq!(p(&["secrets.yaml"]).verb, Verb::Edit);
        // reading a value out in a script
        let d = p(&["-d", "--extract", "[\"github\"][\"pat\"]", "secrets.yaml"]);
        assert_eq!(d.verb, Verb::Decrypt);
        assert_eq!(d.extract.as_deref(), Some("[\"github\"][\"pat\"]"));
        // in-place re-encrypt
        let e = p(&["-e", "-i", "secrets.yaml"]);
        assert!(e.in_place);
        // rekeying after editing .sops.yaml
        assert_eq!(p(&["updatekeys", "secrets.yaml"]).verb, Verb::UpdateKeys);
    }

    /// The safety property the whole alias rests on: a flag we cannot honour must
    /// be *recorded*, not dropped.
    #[test]
    fn an_unsupported_flag_is_recorded_not_ignored() {
        let inv = p(&["-e", "--shamir-secret-sharing-threshold", "2", "f.yaml"]);
        assert_eq!(inv.unsupported, vec!["--shamir-secret-sharing-threshold"]);
        // and its value did not become the filename
        assert_eq!(inv.file, Some(PathBuf::from("f.yaml")));
    }

    #[test]
    fn an_unsupported_value_flag_does_not_swallow_the_filename() {
        for flag in ["--kms", "-p", "--add-age", "--decryption-order"] {
            let inv = p(&["-e", flag, "somevalue", "f.yaml"]);
            assert_eq!(
                inv.file,
                Some(PathBuf::from("f.yaml")),
                "{flag} ate the filename"
            );
            assert_eq!(inv.unsupported, vec![flag]);
        }
    }

    #[test]
    fn an_unsupported_verb_carries_its_name() {
        assert_eq!(
            p(&["exec-env", "f.yaml", "cmd"]).verb,
            Verb::Unimplemented("exec-env".into())
        );
        assert_eq!(
            p(&["publish", "f.yaml"]).verb,
            Verb::Unimplemented("publish".into())
        );
    }

    #[test]
    fn a_missing_value_is_an_error_not_a_default() {
        let args = ["-e".to_string(), "--age".to_string()];
        assert_eq!(parse(&args), Err(ParseError::MissingValue("--age".into())));
    }

    #[test]
    fn a_non_numeric_indent_is_an_error() {
        let args = [
            "--indent".to_string(),
            "two".to_string(),
            "f.yaml".to_string(),
        ];
        assert_eq!(parse(&args), Err(ParseError::NotANumber("two".into())));
    }

    #[test]
    fn an_unknown_flag_is_refused_rather_than_ignored() {
        let args = ["--frobnicate".to_string(), "f.yaml".to_string()];
        assert_eq!(
            parse(&args),
            Err(ParseError::UnknownFlag("--frobnicate".into()))
        );
    }

    #[test]
    fn two_files_are_refused() {
        let args = ["-d".to_string(), "a.yaml".to_string(), "b.yaml".to_string()];
        assert!(matches!(parse(&args), Err(ParseError::TooManyFiles { .. })));
    }

    /// `filestatus` is not a file named "filestatus". A verb-shaped first token is
    /// a verb; anything else is the file.
    #[test]
    fn a_file_whose_name_is_not_a_verb_is_a_file() {
        let inv = p(&["my-verb-ish-file.yaml"]);
        assert_eq!(inv.verb, Verb::Edit);
        assert_eq!(inv.file, Some(PathBuf::from("my-verb-ish-file.yaml")));
    }

    #[test]
    fn the_version_check_flag_is_understood_because_it_blocks_the_network() {
        assert!(p(&["--disable-version-check", "-v"]).disable_version_check);
        assert!(!p(&["-v"]).disable_version_check);
    }

    #[test]
    fn help_says_which_binary_is_answering() {
        let h = help_text();
        assert!(h.contains("suminuri"), "must identify itself");
        assert!(h.contains("It is NOT sops"), "an alias must be diagnosable");
        assert!(
            h.contains("NOT IMPLEMENTED"),
            "the gaps must be visible in --help"
        );
    }

    #[test]
    fn version_names_both_its_own_release_and_the_wire_format() {
        let v = version_text();
        assert!(v.contains(env!("CARGO_PKG_VERSION")));
        assert!(v.contains(suminuri_wire::FORMAT_VERSION));
    }
}
