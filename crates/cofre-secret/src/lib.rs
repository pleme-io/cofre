//! `cofre-secret` — a credential type, and the sanctioned ways to hand one to
//! a subprocess.
//!
//! # The problem
//!
//! A credential held in a `String` is indistinguishable from a path, a URL or
//! a log line. `format!` will interpolate it, `Command::arg` will accept it,
//! and `{:?}` will print it — none of which requires the author to intend any
//! of it. Anything placed in argv is readable from the process table by any
//! local user for the lifetime of the child.
//!
//! # The two rules
//!
//! 1. **A credential is a [`Secret`], never a `String`.** There is no
//!    `Display`, no `Deref<Target = str>`, no `AsRef<str>`, no `AsRef<OsStr>`
//!    and no `Into<String>`. `Debug` prints `Secret(***)`. Consequently a
//!    `Secret` *cannot be passed to [`std::process::Command::arg`] at all* —
//!    it satisfies no bound that method accepts, so putting a credential on a
//!    command line is a compile error rather than a review finding.
//!
//! 2. **A credential reaches a subprocess only through [`SecureCommand`]**,
//!    by one of two sinks: the child's environment
//!    ([`SecureCommand::env_secret`], readable only by the same uid) or the
//!    child's stdin ([`SecureCommand::stdin_secret`], the `--password-stdin`
//!    shape most tools already support).
//!
//! # Reading the value
//!
//! [`Secret::expose`] returns the `&str`. It is deliberately named to be
//! greppable: one token a reviewer can search for, rather than an absence to
//! notice.
//!
//! # What this does not defend against
//!
//! This makes leaks unrepresentable *by accident*, not by intent. An author
//! can still call `expose()` and print the result. The property being bought
//! is that every path to a leak now requires typing `expose()`.

#![forbid(unsafe_op_in_unsafe_fn)]

use std::ffi::OsStr;
use std::io::Write;
use std::process::{Command, ExitStatus, Output, Stdio};

/// Why a [`Secret`] could not be constructed.
#[derive(Debug, PartialEq, Eq)]
pub enum SecretError {
    /// The value was empty. An empty credential is not a credential, and
    /// treating one as authentication produces a confusing downstream failure
    /// far from the cause.
    Empty,
    /// The named environment variable was unset.
    MissingEnv(String),
}

impl std::fmt::Display for SecretError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "refusing to build a Secret from an empty value"),
            Self::MissingEnv(k) => write!(f, "environment variable {k} is not set"),
        }
    }
}

impl std::error::Error for SecretError {}

/// A credential.
///
/// Renders as `***` through `Debug`. Implements no other conversion to a
/// string-like type, which is what prevents it reaching argv or a format
/// string.
///
/// ```
/// # use cofre_secret::Secret;
/// let s = Secret::new("hunter2").unwrap();
/// assert_eq!(format!("{s:?}"), "Secret(***)");
/// assert_eq!(s.expose(), "hunter2");
/// ```
///
/// A `Secret` cannot be placed on a command line — this does not compile:
///
/// ```compile_fail
/// # use cofre_secret::Secret;
/// let s = Secret::new("hunter2").unwrap();
/// std::process::Command::new("docker").arg(s);
/// ```
///
/// Nor can it be interpolated into a format string:
///
/// ```compile_fail
/// # use cofre_secret::Secret;
/// let s = Secret::new("hunter2").unwrap();
/// let _ = format!("token={s}");
/// ```
pub struct Secret(String);

impl Secret {
    /// Build a `Secret`, rejecting an empty value.
    ///
    /// # Errors
    /// [`SecretError::Empty`] if `value` is empty.
    pub fn new(value: impl Into<String>) -> Result<Self, SecretError> {
        let v = value.into();
        if v.is_empty() {
            return Err(SecretError::Empty);
        }
        Ok(Self(v))
    }

    /// Read a `Secret` from an environment variable.
    ///
    /// # Errors
    /// [`SecretError::MissingEnv`] if unset, [`SecretError::Empty`] if set to
    /// the empty string — the two are distinguished because "unset" and "set
    /// to nothing" usually have different causes.
    pub fn from_env(key: &str) -> Result<Self, SecretError> {
        match std::env::var(key) {
            Ok(v) => Self::new(v),
            Err(_) => Err(SecretError::MissingEnv(key.to_string())),
        }
    }

    /// The credential itself.
    ///
    /// Named to be greppable. Every leak path goes through this call, so
    /// `rg 'expose\(\)'` enumerates them.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Length in bytes. Useful for logging that a credential was found
    /// without logging what it is.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Always false — an empty `Secret` cannot be constructed. Present because
    /// clippy asks for it alongside `len`.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        false
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(***)")
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        // Best-effort scrub. Not a guarantee: `String` may have reallocated
        // during construction and left copies elsewhere in the heap, and the
        // optimiser is permitted to elide this. Stated plainly rather than
        // presented as zeroization.
        //
        // SAFETY: writing 0x00 over the buffer keeps it valid UTF-8 (NUL is
        // ASCII), which is the invariant `as_bytes_mut` requires the caller to
        // uphold.
        unsafe {
            self.0.as_bytes_mut().fill(0);
        }
    }
}

/// A [`Command`] that a [`Secret`] can only reach through a sanctioned sink.
///
/// `arg`/`args` accept `AsRef<OsStr>`, which `Secret` deliberately does not
/// implement — so the unsafe path is not merely discouraged, it does not
/// typecheck.
///
/// ```no_run
/// # use cofre_secret::{Secret, SecureCommand};
/// let token = Secret::new("ghp_EXAMPLE_not_a_real_token").unwrap();
///
/// // stdin — the `--password-stdin` shape
/// SecureCommand::new("docker")
///     .args(["login", "ghcr.io", "-u", "user", "--password-stdin"])
///     .stdin_secret(&token)
///     .output()
///     .unwrap();
///
/// // environment — uid-scoped
/// SecureCommand::new("gh")
///     .args(["api", "/user"])
///     .env_secret("GH_TOKEN", &token)
///     .status()
///     .unwrap();
/// ```
pub struct SecureCommand {
    inner: Command,
    stdin: Option<String>,
}

impl SecureCommand {
    /// Start building a command.
    pub fn new(program: impl AsRef<OsStr>) -> Self {
        Self {
            inner: Command::new(program),
            stdin: None,
        }
    }

    /// Add one argument. A [`Secret`] cannot be passed here.
    #[must_use]
    pub fn arg(mut self, a: impl AsRef<OsStr>) -> Self {
        self.inner.arg(a);
        self
    }

    /// Add several arguments. A [`Secret`] cannot be passed here.
    #[must_use]
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.inner.args(args);
        self
    }

    /// Set a non-secret environment variable.
    #[must_use]
    pub fn env(mut self, k: impl AsRef<OsStr>, v: impl AsRef<OsStr>) -> Self {
        self.inner.env(k, v);
        self
    }

    /// Set the working directory.
    #[must_use]
    pub fn current_dir(mut self, dir: impl AsRef<std::path::Path>) -> Self {
        self.inner.current_dir(dir);
        self
    }

    /// Pass a credential via the child's environment.
    ///
    /// `/proc/<pid>/environ` is readable only by the owning uid, unlike
    /// `/proc/<pid>/cmdline`, which is world-readable. This is the weaker of
    /// the two sinks — prefer [`Self::stdin_secret`] where the tool supports
    /// it.
    #[must_use]
    pub fn env_secret(mut self, key: impl AsRef<OsStr>, secret: &Secret) -> Self {
        self.inner.env(key, secret.expose());
        self
    }

    /// Pass a credential on the child's stdin.
    ///
    /// The strongest sink available: the value exists only in a pipe between
    /// two processes. Most tools that accept a credential support this
    /// (`docker login --password-stdin`, `helm registry login
    /// --password-stdin`, `skopeo login --password-stdin`, `gh secret set`
    /// reading stdin).
    ///
    /// Calling this twice replaces the earlier value.
    #[must_use]
    pub fn stdin_secret(mut self, secret: &Secret) -> Self {
        self.stdin = Some(secret.expose().to_string());
        self
    }

    /// Run to completion, capturing output.
    ///
    /// # Errors
    /// Propagates spawn/IO failures.
    pub fn output(mut self) -> std::io::Result<Output> {
        let Some(payload) = self.stdin.take() else {
            return self.inner.output();
        };
        self.inner.stdin(Stdio::piped());
        self.inner.stdout(Stdio::piped());
        self.inner.stderr(Stdio::piped());
        let mut child = self.inner.spawn()?;
        // `take()` so the pipe is dropped (and the child sees EOF) before we
        // wait — otherwise a tool that reads stdin to EOF deadlocks.
        if let Some(mut sink) = child.stdin.take() {
            sink.write_all(payload.as_bytes())?;
        }
        child.wait_with_output()
    }

    /// Run to completion, inheriting stdio.
    ///
    /// # Errors
    /// Propagates spawn/IO failures.
    pub fn status(mut self) -> std::io::Result<ExitStatus> {
        let Some(payload) = self.stdin.take() else {
            return self.inner.status();
        };
        self.inner.stdin(Stdio::piped());
        let mut child = self.inner.spawn()?;
        if let Some(mut sink) = child.stdin.take() {
            sink.write_all(payload.as_bytes())?;
        }
        child.wait()
    }

    /// The arguments as configured. Exposed so a consumer can assert its own
    /// no-credential-in-argv property, as this crate's tests do.
    pub fn debug_args(&self) -> Vec<String> {
        self.inner
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }
}

impl std::fmt::Debug for SecureCommand {
    /// Prints the program and arguments but never the stdin payload.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureCommand")
            .field("program", &self.inner.get_program())
            .field("args", &self.debug_args())
            .field("stdin_secret", &self.stdin.as_ref().map(|_| "***"))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Credential-SHAPED so the tests exercise real matching, and carrying an
    /// explicit marker so a scanner can tell it is a fixture. The pre-commit
    /// gate honours this convention; without it, a crate that tests credential
    /// handling cannot commit its own tests.
    const TOKEN: &str = "ghp_EXAMPLENOTAREALTOKENxxxxxxxxxxxxxxxx";

    #[test]
    fn debug_does_not_render_the_value() {
        let s = Secret::new(TOKEN).unwrap();
        let rendered = format!("{s:?}");
        assert_eq!(rendered, "Secret(***)");
        assert!(!rendered.contains(TOKEN));
    }

    #[test]
    fn empty_is_refused() {
        assert!(matches!(Secret::new(""), Err(SecretError::Empty)));
    }

    #[test]
    fn a_secret_never_reaches_argv_via_either_sink() {
        let token = Secret::new(TOKEN).unwrap();

        let via_stdin = SecureCommand::new("docker")
            .args(["login", "--password-stdin"])
            .stdin_secret(&token);
        let argv = via_stdin.debug_args().join(" ");
        assert!(!argv.contains(TOKEN), "secret reached argv: {argv}");
        assert!(!format!("{via_stdin:?}").contains(TOKEN));

        let via_env = SecureCommand::new("gh")
            .arg("api")
            .env_secret("GH_TOKEN", &token);
        let argv = via_env.debug_args().join(" ");
        assert!(!argv.contains(TOKEN), "secret reached argv: {argv}");
        assert!(!format!("{via_env:?}").contains(TOKEN));
    }

    #[test]
    fn stdin_sink_actually_delivers_the_value() {
        let token = Secret::new(TOKEN).unwrap();
        let out = SecureCommand::new("cat")
            .stdin_secret(&token)
            .output()
            .unwrap();
        assert_eq!(String::from_utf8_lossy(&out.stdout), TOKEN);
    }

    #[test]
    fn env_sink_actually_delivers_the_value() {
        let token = Secret::new(TOKEN).unwrap();
        let out = SecureCommand::new("sh")
            .args(["-c", "printf %s \"$TEST_TOKEN\""])
            .env_secret("TEST_TOKEN", &token)
            .output()
            .unwrap();
        assert_eq!(String::from_utf8_lossy(&out.stdout), TOKEN);
    }

    #[test]
    fn from_env_distinguishes_unset_from_empty() {
        // SAFETY: single-threaded test, variable is unique to this test.
        unsafe { std::env::remove_var("COFRE_SECRET_TEST_A") };
        assert!(matches!(
            Secret::from_env("COFRE_SECRET_TEST_A"),
            Err(SecretError::MissingEnv(_))
        ));

        unsafe { std::env::set_var("COFRE_SECRET_TEST_A", "") };
        assert!(matches!(
            Secret::from_env("COFRE_SECRET_TEST_A"),
            Err(SecretError::Empty)
        ));

        unsafe { std::env::remove_var("COFRE_SECRET_TEST_A") };
    }
}
