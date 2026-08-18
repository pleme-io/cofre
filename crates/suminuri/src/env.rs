//! The `Environment` seam.
//!
//! Every side effect this tool can have — reading a file, writing one, reading an
//! environment variable, asking the clock, spawning an editor — goes through this
//! trait. That is the TYPED-SPEC + INTERPRETER discipline: the interpreter is
//! `apply<E: Environment>`, so the whole of it is exercisable against a mock with
//! zero real side effects.
//!
//! It matters more than usual here. The alternative is tests that write real
//! files with real keys, which means either a test suite that cannot run in CI or
//! one that leaves plaintext secrets in `/tmp`. A mock removes both.
//!
//! # Two things the trait deliberately forbids
//!
//! - **No `command(…)` returning a shell.** The only subprocess this tool ever
//!   spawns is an editor, so that is the only subprocess method — named
//!   [`Environment::edit_file`]. A general "run this string" method is how a
//!   no-shell tool acquires a shell.
//! - **No `write_file` without a mode.** A secret written 0644 is a secret
//!   leaked, and a defaulted mode is how that happens. The mode is a required
//!   parameter of [`Environment::write_file_atomic`].

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};

/// Everything outside the process.
pub trait Environment {
    /// An environment variable, or `None` when unset **or empty**.
    ///
    /// Collapsing empty into unset matches how sops tests its own env vars
    /// (`!= ""`), so `SOPS_AGE_KEY=` behaves the same in both tools.
    fn var(&self, key: &str) -> Option<String>;

    fn read_to_string(&self, path: &Path) -> io::Result<String>;

    /// Write atomically, with the mode applied **before** the contents are
    /// visible at `path`.
    ///
    /// Order is the whole point: writing then chmod-ing leaves a window in which
    /// a secret file is world-readable. Implementations write to a temporary in
    /// the same directory, set the mode there, then rename.
    fn write_file_atomic(&self, path: &Path, contents: &str, mode: u32) -> io::Result<()>;

    fn exists(&self, path: &Path) -> bool;

    /// Now, as the RFC 3339 string that goes into `sops.lastmodified`.
    ///
    /// Returns the *string*, not a timestamp, because that string is the MAC
    /// field's AAD — so the formatting decision belongs to whoever owns the wire,
    /// not to each caller.
    fn now_rfc3339(&self) -> String;

    /// Open `path` in the operator's editor and wait. Returns whether the file
    /// changed, which is what drives sops's exit code 200.
    fn edit_file(&self, path: &Path) -> io::Result<bool>;

    /// A private directory for plaintext that must briefly touch a filesystem.
    ///
    /// Named `secure` because the implementation is expected to prefer a
    /// memory-backed filesystem where one exists — the RAMDISK doctrine's point
    /// that a drive is where undeclared state hides.
    fn secure_temp_dir(&self) -> io::Result<PathBuf>;
}

/// The real one.
pub struct RealEnvironment;

impl Environment for RealEnvironment {
    fn var(&self, key: &str) -> Option<String> {
        std::env::var(key).ok().filter(|v| !v.is_empty())
    }

    fn read_to_string(&self, path: &Path) -> io::Result<String> {
        std::fs::read_to_string(path)
    }

    fn write_file_atomic(&self, path: &Path, contents: &str, mode: u32) -> io::Result<()> {
        let dir = path.parent().unwrap_or(Path::new("."));
        // Same directory, so the rename is atomic — a temp in /tmp would be a
        // cross-device copy with a visible partial state.
        let tmp = dir.join(format!(
            ".{}.suminuri.tmp",
            path.file_name().and_then(|n| n.to_str()).unwrap_or("out")
        ));
        std::fs::write(&tmp, contents)?;
        set_mode(&tmp, mode)?;
        match std::fs::rename(&tmp, path) {
            Ok(()) => Ok(()),
            Err(e) => {
                // Never leave a temp holding plaintext behind.
                let _ = std::fs::remove_file(&tmp);
                Err(e)
            }
        }
    }

    fn exists(&self, path: &Path) -> bool {
        path.exists()
    }

    fn now_rfc3339(&self) -> String {
        // Formatted by hand from the epoch rather than pulling in `chrono` or
        // `time`: the output is a fixed shape (`YYYY-MM-DDTHH:MM:SSZ`, UTC, no
        // fractional part) because it is a wire field, and a date library would
        // add a dependency plus the standing risk that a version bump changes the
        // rendering of an AAD.
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        format_rfc3339_utc(secs)
    }

    fn edit_file(&self, path: &Path) -> io::Result<bool> {
        let before = std::fs::read(path)?;
        let editor = self
            .var("SOPS_EDITOR")
            .or_else(|| self.var("EDITOR"))
            // sops's own default. Reproduced so an operator with no $EDITOR gets
            // the same behaviour from both tools.
            .unwrap_or_else(|| "vim".to_string());
        // The editor command may carry arguments (`code --wait`), which is why it
        // is split — but on whitespace only. No shell, no globbing, no
        // substitution: the string is an argv, not a command line.
        let mut parts = editor.split_whitespace();
        let program = parts.next().unwrap_or("vim");
        let status = std::process::Command::new(program)
            .args(parts)
            .arg(path)
            .status()?;
        if !status.success() {
            return Err(io::Error::other(format!(
                "editor `{editor}` exited with {status}"
            )));
        }
        Ok(std::fs::read(path)? != before)
    }

    fn secure_temp_dir(&self) -> io::Result<PathBuf> {
        // On darwin `/tmp` is on-disk; there is no per-user tmpfs to prefer, so
        // the honest answer is the OS temp dir with a 0700 subdirectory. Stated
        // rather than dressed up: this is only-mitigated, not unrepresentable —
        // plaintext does briefly reach a disk during `edit`.
        let dir = std::env::temp_dir().join(format!("suminuri-{}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        set_mode(&dir, 0o700)?;
        Ok(dir)
    }
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> io::Result<()> {
    // No POSIX modes. A caller that needs the guarantee should refuse to run
    // here rather than believe a silent success.
    Ok(())
}

/// `YYYY-MM-DDTHH:MM:SSZ` from a Unix timestamp, in UTC.
///
/// Civil-from-days is Howard Hinnant's algorithm, valid for the proleptic
/// Gregorian calendar — the same one every date library uses under the hood.
#[must_use]
pub fn format_rfc3339_utc(secs: u64) -> String {
    let days = i64::try_from(secs / 86_400).unwrap_or(0);
    let rem = secs % 86_400;
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);

    // days since 1970-01-01 -> civil date
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// A mock environment: an in-memory filesystem, a fixed clock, no subprocesses.
#[derive(Default)]
pub struct MockEnvironment {
    vars: HashMap<String, String>,
    files: std::cell::RefCell<HashMap<PathBuf, String>>,
    modes: std::cell::RefCell<HashMap<PathBuf, u32>>,
    now: String,
    /// What an `edit_file` call should write, and whether it counts as a change.
    edit_result: Option<(String, bool)>,
}

impl MockEnvironment {
    #[must_use]
    pub fn new() -> Self {
        Self {
            now: "2026-08-18T00:00:00Z".to_string(),
            ..Self::default()
        }
    }

    #[must_use]
    pub fn with_var(mut self, k: &str, v: &str) -> Self {
        self.vars.insert(k.to_string(), v.to_string());
        self
    }

    #[must_use]
    pub fn with_file(self, path: &str, contents: &str) -> Self {
        self.files
            .borrow_mut()
            .insert(PathBuf::from(path), contents.to_string());
        self
    }

    #[must_use]
    pub fn with_now(mut self, now: &str) -> Self {
        self.now = now.to_string();
        self
    }

    /// Make `edit_file` replace the file with `contents`.
    #[must_use]
    pub fn with_editor_writing(mut self, contents: &str, changed: bool) -> Self {
        self.edit_result = Some((contents.to_string(), changed));
        self
    }

    /// What is at `path` now.
    #[must_use]
    pub fn file(&self, path: &str) -> Option<String> {
        self.files.borrow().get(Path::new(path)).cloned()
    }

    /// The mode a written file got. `None` if it was never written by us.
    #[must_use]
    pub fn mode(&self, path: &str) -> Option<u32> {
        self.modes.borrow().get(Path::new(path)).copied()
    }
}

impl Environment for MockEnvironment {
    fn var(&self, key: &str) -> Option<String> {
        self.vars.get(key).cloned().filter(|v| !v.is_empty())
    }

    fn read_to_string(&self, path: &Path) -> io::Result<String> {
        self.files
            .borrow()
            .get(path)
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, path.display().to_string()))
    }

    fn write_file_atomic(&self, path: &Path, contents: &str, mode: u32) -> io::Result<()> {
        self.files
            .borrow_mut()
            .insert(path.to_path_buf(), contents.to_string());
        self.modes.borrow_mut().insert(path.to_path_buf(), mode);
        Ok(())
    }

    fn exists(&self, path: &Path) -> bool {
        self.files.borrow().contains_key(path)
    }

    fn now_rfc3339(&self) -> String {
        self.now.clone()
    }

    fn edit_file(&self, path: &Path) -> io::Result<bool> {
        match &self.edit_result {
            Some((contents, changed)) => {
                self.files
                    .borrow_mut()
                    .insert(path.to_path_buf(), contents.clone());
                Ok(*changed)
            }
            None => Ok(false),
        }
    }

    fn secure_temp_dir(&self) -> io::Result<PathBuf> {
        Ok(PathBuf::from("/mock-tmp"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_matches_known_timestamps() {
        assert_eq!(format_rfc3339_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_rfc3339_utc(1_000_000_000), "2001-09-09T01:46:40Z");
        // The lastmodified from the operator's real secrets.yaml. The epoch was
        // wrong in the first draft of this test (off by four days) and the four
        // rows around it still passed — which is why a hand-authored magic
        // timestamp is worth checking against an independent converter rather
        // than trusting.
        assert_eq!(format_rfc3339_utc(1_786_665_989), "2026-08-14T00:06:29Z");
        // A leap day, which is where a hand-rolled calendar goes wrong.
        assert_eq!(format_rfc3339_utc(1_709_164_800), "2024-02-29T00:00:00Z");
        assert_eq!(format_rfc3339_utc(951_782_400), "2000-02-29T00:00:00Z");
    }

    #[test]
    fn an_empty_variable_reads_as_unset_like_sops() {
        let env = MockEnvironment::new().with_var("SOPS_AGE_KEY", "");
        assert_eq!(env.var("SOPS_AGE_KEY"), None);
    }

    #[test]
    fn the_mock_records_the_mode_a_write_asked_for() {
        let env = MockEnvironment::new();
        env.write_file_atomic(Path::new("/out.yaml"), "body", 0o600)
            .expect("write");
        assert_eq!(env.file("/out.yaml").as_deref(), Some("body"));
        assert_eq!(env.mode("/out.yaml"), Some(0o600));
    }

    #[test]
    fn a_missing_file_is_not_found_not_a_panic() {
        let env = MockEnvironment::new();
        let err = env.read_to_string(Path::new("/nope")).expect_err("missing");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn the_mock_editor_reports_whether_it_changed_anything() {
        let env = MockEnvironment::new()
            .with_file("/f.yaml", "before")
            .with_editor_writing("after", true);
        assert!(env.edit_file(Path::new("/f.yaml")).expect("edit"));
        assert_eq!(env.file("/f.yaml").as_deref(), Some("after"));

        let quiet = MockEnvironment::new().with_file("/f.yaml", "before");
        assert!(
            !quiet.edit_file(Path::new("/f.yaml")).expect("edit"),
            "no change"
        );
    }
}
