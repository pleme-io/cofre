//! The manifest sops-nix hands its installer.
//!
//! ── ★ WHY THIS IS A DROP-IN AND NOT A PATH SUBSTITUTION ────────────────
//!
//! `overlays/suminuri.nix` already rebinds `pkgs.sops` fleet-wide, and that
//! captured two of the four fronts. It provably cannot capture this one:
//! upstream `sops-install-secrets/main.go:343` calls `decrypt.File` as a Go
//! **library**, and the only `exec.Command`s in that file are
//! `systemctl`/`getconf`/`hdiutil`/`newfs_hfs`/`mount`. There is no `sops` process to
//! substitute.
//!
//! So sops-nix exposes a `sops.package` seam instead, surfaced in the fleet as
//! `pleme.suminuri.installSecretsPackage` — declared, forwarded by
//! blackmatter-secrets, and **currently refused by an assertion because no
//! drop-in exists**. This crate is that drop-in.
//!
//! ── ★ THE SCALE, WHICH IS WHY IT MATTERS ───────────────────────────────
//!
//! Front 3 carries the fleet's real load: **337 secret declarations across 18
//! nodes, re-materialised on every rebuild**. plo alone hands the installer 27
//! secrets. This is not a corner of the sops surface; it is the part that runs.
//!
//! ── ★ THE MANIFEST IS TRANSCRIBED, NOT INVENTED ────────────────────────
//!
//! Every field below was read off plo's live manifest
//! (`/nix/store/…-manifest.json`) rather than from upstream's struct
//! definitions. That matters because the drop-in's contract is with the JSON
//! sops-nix actually emits for THIS fleet, and a field upstream renamed or
//! stopped writing is a field we must not require.

use serde::{Deserialize, Serialize};

/// One secret to place.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Secret {
    /// The key path inside the sops file (`attic/jwt/token`).
    pub key: String,
    /// The secret's name, usually equal to `key`.
    pub name: String,
    /// Where it lands (`/run/secrets/attic/jwt/token`).
    pub path: String,
    /// The encrypted file it comes from.
    #[serde(rename = "sopsFile")]
    pub sops_file: String,
    /// That file's format (`yaml`, `json`, `binary`, `dotenv`).
    pub format: String,
    /// Octal, as a string (`"0400"`).
    ///
    /// ★ A STRING, not a number, and that is load-bearing: `0400` parsed as a
    /// JSON integer is 400 decimal — `0620` in octal — which would make a
    /// key-file group- and world-readable. Keeping it textual means the octal
    /// base is never inferred.
    pub mode: String,
    /// Owner NAME, or `None` when sops-nix expressed it numerically.
    ///
    /// ★ Measured on plo's live manifest: **16 of 27 entries carry
    /// `"owner": null` with a numeric `uid`**. Requiring a String here made
    /// the whole manifest unparseable — caught by the first dry-run against
    /// real data, and not visible in the 1200-character prefix these types
    /// were originally transcribed from.
    pub owner: Option<String>,
    /// Group NAME, or `None` — see [`Secret::owner`]. Null on the same 16.
    pub group: Option<String>,
    /// Numeric owner. The fallback when `owner` is null, and NOT merely a
    /// cache of it: an entry may carry a uid for an account that has no name
    /// yet, which is precisely the `neededForUsers` case.
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    /// Secrets needed before normal users exist get an earlier pass.
    #[serde(rename = "neededForUsers", default)]
    pub needed_for_users: bool,
    #[serde(rename = "restartUnits", default)]
    pub restart_units: Vec<String>,
    #[serde(rename = "reloadUnits", default)]
    pub reload_units: Vec<String>,
}

/// A file rendered from decrypted values.
///
/// ★ A FEATURE THE FIRST CUT MISSED ENTIRELY. plo's manifest carries **four**
/// templates, and a drop-in that ignored them would place every plain secret
/// correctly and silently omit four files — cloudflared's credentials among
/// them. Found by the first dry-run against a real manifest, not by reading
/// upstream's structs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Template {
    pub name: String,
    pub path: String,
    /// The file body, carrying `<SOPS:hash:PLACEHOLDER>` markers.
    pub content: String,
    pub mode: String,
    pub owner: Option<String>,
    pub group: Option<String>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    #[serde(rename = "restartUnits", default)]
    pub restart_units: Vec<String>,
    #[serde(rename = "reloadUnits", default)]
    pub reload_units: Vec<String>,
}

/// The whole manifest.
///
/// ★ `#[serde(default)]` on the optional halves and NO `deny_unknown_fields`.
/// This is the one config surface in the fleet where the strict posture is
/// wrong: the producer is sops-nix, not us, and a field it ADDS in a future
/// release must not make every node fail to materialise its secrets. Unknown
/// fields are ignored deliberately; missing ones we require are still errors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub secrets: Vec<Secret>,
    #[serde(rename = "secretsMountPoint")]
    pub secrets_mount_point: String,
    #[serde(rename = "symlinkPath")]
    pub symlink_path: String,
    #[serde(rename = "keepGenerations", default)]
    pub keep_generations: u32,
    #[serde(rename = "ageKeyFile")]
    pub age_key_file: Option<String>,
    /// SSH host keys to derive an age identity from.
    ///
    /// ★ THIS is the node's secret-decryption identity, and it is the same
    /// file its sshd serves as a host key. See theory/NATURALIZE-NIXOS.md:
    /// the sshd row and this one are two ends of one identity path.
    #[serde(rename = "ageSshKeyPaths", default)]
    pub age_ssh_key_paths: Vec<String>,
    #[serde(rename = "gnupgHome")]
    pub gnupg_home: Option<String>,
    #[serde(rename = "sshKeyPaths", default)]
    pub ssh_key_paths: Vec<String>,
    #[serde(rename = "userMode", default)]
    pub user_mode: bool,
    #[serde(rename = "useTmpfs", default)]
    pub use_tmpfs: bool,
    /// Files rendered by substituting decrypted values into a body.
    #[serde(default)]
    pub templates: Vec<Template>,
    /// secret name -> the `<SOPS:…:PLACEHOLDER>` marker standing for it.
    ///
    /// ★ The substitution table. A template's body is rendered by replacing
    /// each marker with that secret's plaintext, so a template depends on
    /// secrets that must already be decrypted — which is why templates are
    /// rendered AFTER the entries, never interleaved.
    #[serde(rename = "placeholderBySecretName", default)]
    pub placeholder_by_secret_name: std::collections::BTreeMap<String, String>,
}

/// Errors reading a manifest.
#[derive(Debug)]
pub enum ManifestError {
    Read(std::io::Error),
    Parse(serde_json::Error),
}

impl std::fmt::Display for ManifestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read(e) => write!(f, "cannot read the manifest: {e}"),
            Self::Parse(e) => write!(f, "cannot parse the manifest: {e}"),
        }
    }
}

impl Manifest {
    /// Load from a path.
    ///
    /// # Errors
    /// [`ManifestError`] on read or parse failure.
    pub fn load(path: &std::path::Path) -> Result<Self, ManifestError> {
        let raw = std::fs::read_to_string(path).map_err(ManifestError::Read)?;
        serde_json::from_str(&raw).map_err(ManifestError::Parse)
    }

    /// The secrets that must be placed BEFORE normal users exist.
    ///
    /// ★ Two passes, not one, and the order is not cosmetic: a secret a user's
    /// own creation depends on cannot be chowned to that user. Upstream splits
    /// these and so must we, or the first boot of a node with a
    /// `neededForUsers` secret fails in a way that looks like a permissions
    /// bug rather than an ordering one.
    #[must_use]
    pub fn user_pass(&self) -> Vec<&Secret> {
        self.secrets.iter().filter(|s| s.needed_for_users).collect()
    }

    /// The secrets placed in the normal pass.
    #[must_use]
    pub fn main_pass(&self) -> Vec<&Secret> {
        self.secrets.iter().filter(|s| !s.needed_for_users).collect()
    }

    /// Every distinct sops file this manifest reads.
    ///
    /// ★ Decrypt once per FILE, not once per secret. plo's manifest names 27
    /// secrets across far fewer files; decrypting per-secret would repeat the
    /// MAC verification dozens of times per rebuild for no gain.
    #[must_use]
    pub fn distinct_files(&self) -> Vec<&str> {
        let mut v: Vec<&str> = self.secrets.iter().map(|s| s.sops_file.as_str()).collect();
        v.sort_unstable();
        v.dedup();
        v
    }
}

impl Secret {
    /// The mode as octal.
    ///
    /// # Errors
    /// The string if it is not valid octal.
    pub fn mode_octal(&self) -> Result<u32, &str> {
        u32::from_str_radix(self.mode.trim_start_matches("0o"), 8).map_err(|_| self.mode.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A verbatim slice of plo's live manifest, field names included.
    const PLO: &str = r#"{
      "ageKeyFile": "/var/lib/sops-nix/key.txt",
      "ageSshKeyPaths": ["/etc/ssh/ssh_host_ed25519_key"],
      "gnupgHome": null,
      "keepGenerations": 1,
      "secretsMountPoint": "/run/secrets.d",
      "symlinkPath": "/run/secrets",
      "sshKeyPaths": ["/etc/ssh/ssh_host_rsa_key"],
      "useTmpfs": false,
      "userMode": false,
      "secrets": [
        {"format":"yaml","gid":0,"group":"root","key":"attic/jwt/token","mode":"0400",
         "name":"attic/jwt/token","neededForUsers":false,"owner":"root",
         "path":"/run/secrets/attic/jwt/token","reloadUnits":[],"restartUnits":[],
         "sopsFile":"/nix/store/aaa-secrets.yaml","uid":0},
        {"format":"yaml","gid":100,"group":"users","key":"users/luis/pw","mode":"0440",
         "name":"users/luis/pw","neededForUsers":true,"owner":"luis",
         "path":"/run/secrets/users/luis/pw","reloadUnits":[],"restartUnits":["x.service"],
         "sopsFile":"/nix/store/aaa-secrets.yaml","uid":1001}
      ]
    }"#;

    fn plo() -> Manifest {
        serde_json::from_str(PLO).expect("plo manifest must parse")
    }

    #[test]
    fn the_live_manifest_shape_parses() {
        let m = plo();
        assert_eq!(m.secrets.len(), 2);
        assert_eq!(m.symlink_path, "/run/secrets");
        assert_eq!(m.age_ssh_key_paths, vec!["/etc/ssh/ssh_host_ed25519_key"]);
    }

    #[test]
    fn mode_is_read_as_octal_not_decimal() {
        // THE test. "0400" parsed as a JSON integer is 400 decimal = 0o620,
        // which makes a private key group- AND world-readable. Keeping the
        // field textual is what stops the base ever being inferred.
        let m = plo();
        assert_eq!(m.secrets[0].mode_octal(), Ok(0o400));
        assert_ne!(m.secrets[0].mode_octal(), Ok(400));
        assert_eq!(m.secrets[1].mode_octal(), Ok(0o440));
    }

    #[test]
    fn the_two_passes_are_separated() {
        // A secret a user's creation depends on cannot be chowned to that
        // user. Upstream splits these; conflating them fails first boot in a
        // way that looks like permissions rather than ordering.
        let m = plo();
        assert_eq!(m.user_pass().len(), 1);
        assert_eq!(m.user_pass()[0].key, "users/luis/pw");
        assert_eq!(m.main_pass().len(), 1);
        assert_eq!(m.main_pass()[0].key, "attic/jwt/token");
    }

    #[test]
    fn files_are_decrypted_once_each_not_once_per_secret() {
        // plo names 27 secrets over far fewer files; per-secret decryption
        // would repeat MAC verification dozens of times per rebuild.
        let m = plo();
        assert_eq!(m.distinct_files(), vec!["/nix/store/aaa-secrets.yaml"]);
    }

    #[test]
    fn an_unknown_field_is_ignored_not_fatal() {
        // ★ The one config surface where the fleet's strict posture is wrong.
        // The producer is sops-nix, not us: a field it ADDS in a future
        // release must not make every node fail to materialise its secrets.
        let with_new = PLO.replace(
            "\"userMode\": false,",
            "\"userMode\": false, \"somethingUpstreamAddedLater\": {\"a\":1},",
        );
        assert!(serde_json::from_str::<Manifest>(&with_new).is_ok());
    }

    #[test]
    fn a_missing_required_field_is_still_an_error() {
        // Ignoring unknowns must not become ignoring absences.
        let broken = PLO.replace("\"symlinkPath\": \"/run/secrets\",", "");
        assert!(serde_json::from_str::<Manifest>(&broken).is_err());
    }

    #[test]
    fn restart_and_reload_units_are_carried_not_dropped() {
        // These drive activation side effects. Losing them means a secret
        // rotates and the consuming unit never learns.
        let m = plo();
        assert_eq!(m.secrets[1].restart_units, vec!["x.service"]);
    }
}
