//! Pins the difference between `write_secret` and a write-then-chmod.
//!
//! Kept permanently rather than run once: if `write_secret` ever regresses to
//! setting the mode after creation, this goes red.

use std::os::unix::fs::PermissionsExt;

unsafe extern "C" {
    #[link_name = "umask"]
    fn libc_umask(m: u32) -> u32;
}

/// Write first, set permissions after.
fn old_pattern(path: &std::path::Path, bytes: &[u8], mode: u32) -> std::io::Result<u32> {
    std::fs::write(path, bytes)?; // creates 0666 & ~umask
    let during = std::fs::metadata(path)?.permissions().mode() & 0o777;
    std::fs::set_permissions(path, PermissionsExt::from_mode(mode))?; // too late
    Ok(during)
}

#[test]
fn the_old_pattern_opens_a_world_readable_window_and_the_new_one_does_not() {
    let d = std::env::temp_dir().join(format!("cofre-fs-redrun-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();

    let prev = unsafe { libc_umask(0o000) };

    // OLD: mode during the window is NOT the requested mode.
    let old = d.join("old");
    let during = old_pattern(&old, b"master-age-key", 0o600).unwrap();
    let old_final = std::fs::metadata(&old).unwrap().permissions().mode() & 0o777;

    // NEW: never observable at anything but the requested mode.
    let new = d.join("new");
    cofre_fs::write_secret(&new, b"master-age-key", 0o600).unwrap();
    let new_final = std::fs::metadata(&new).unwrap().permissions().mode() & 0o777;

    unsafe { libc_umask(prev) };

    assert_ne!(
        during, 0o600,
        "old pattern should expose a window; it did not — the test lost its teeth"
    );
    assert!(
        during & 0o044 != 0,
        "the window should be group/world-readable, was {during:o}"
    );
    assert_eq!(
        old_final, 0o600,
        "the write-then-chmod final mode is correct, which is why asserting \
         only the final mode does not distinguish the two"
    );
    assert_eq!(new_final, 0o600, "write_secret must land on the requested mode");

    let _ = std::fs::remove_dir_all(&d);
}
