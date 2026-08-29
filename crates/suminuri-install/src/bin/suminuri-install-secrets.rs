//! `suminuri-install-secrets` — the pleme-io-native name.
//!
//! The same program as `sops-install-secrets`; see `entry.rs` for why both
//! names ship and why the entry point is a library function rather than a file
//! either binary owns.
fn main() -> std::process::ExitCode {
    suminuri_install::entry::run()
}
