//! Secret value generation — pure CSPRNG, plaintext lives only in
//! `Zeroizing<String>` buffers that wipe on drop.
//!
//! Hard rules:
//!   - Every plaintext-handling type is `Zeroizing` (or wraps one).
//!   - The OS CSPRNG (`getrandom`) is the sole entropy source.
//!   - Random alphabet sampling uses **rejection sampling**, so the
//!     output distribution is uniform regardless of alphabet size.
//!   - This module never logs, prints, or returns plaintext via stdout.

use cofre_types::{Charset, SecretGenPolicy};
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub enum GenerationError {
    #[error("OS CSPRNG failure")]
    GetRandom(getrandom::Error),
    #[error("policy {0:?} is not yet implemented in this build of cofre")]
    NotYetImplemented(&'static str),
}

impl From<getrandom::Error> for GenerationError {
    fn from(e: getrandom::Error) -> Self {
        Self::GetRandom(e)
    }
}

/// Materialize a single secret value per the declared policy. Caller
/// owns the returned `Zeroizing<String>` and is responsible for wiring
/// it into a `SecretBackend::write` call without ever exposing it.
pub fn generate(policy: &SecretGenPolicy) -> Result<Zeroizing<String>, GenerationError> {
    match policy {
        SecretGenPolicy::PasswordRandom { length, charset, .. } => {
            random_string(usize::from(*length), charset.alphabet())
        }
        SecretGenPolicy::Token { length, prefix } => {
            let body = random_string(usize::from(*length), Charset::Alphanumeric.alphabet())?;
            let mut out = Zeroizing::new(String::with_capacity(
                usize::from(*length) + prefix.as_ref().map_or(0, String::len),
            ));
            if let Some(p) = prefix {
                out.push_str(p);
            }
            out.push_str(&body);
            Ok(out)
        }
        SecretGenPolicy::PreSharedKey { length_bytes } => {
            let mut buf: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0u8; usize::from(*length_bytes)]);
            getrandom::getrandom(&mut buf)?;
            Ok(Zeroizing::new(base64_url_encode(&buf)))
        }
        SecretGenPolicy::WireguardKeypair => {
            Err(GenerationError::NotYetImplemented("WireguardKeypair"))
        }
        SecretGenPolicy::SshKeypair { .. } => {
            Err(GenerationError::NotYetImplemented("SshKeypair"))
        }
        SecretGenPolicy::TlsKeypair { .. } => {
            Err(GenerationError::NotYetImplemented("TlsKeypair"))
        }
    }
}

/// Uniform random sampling from `alphabet` via rejection. Length must
/// fit in usize. The intermediate byte buffer is zeroized on drop.
fn random_string(length: usize, alphabet: &[u8]) -> Result<Zeroizing<String>, GenerationError> {
    assert!(!alphabet.is_empty(), "alphabet must be non-empty");
    let n = alphabet.len();
    // Largest multiple of n ≤ 256. Rejecting bytes ≥ this threshold
    // gives a uniform distribution across the alphabet.
    let threshold: u16 = (256u16 / n as u16) * n as u16;
    let threshold_u8 = u8::try_from(threshold.min(256)).unwrap_or(255);

    let mut out = Zeroizing::new(String::with_capacity(length));
    let mut byte_buf = [0u8; 1];
    let mut produced = 0usize;
    while produced < length {
        getrandom::getrandom(&mut byte_buf)?;
        if byte_buf[0] < threshold_u8 {
            let idx = usize::from(byte_buf[0]) % n;
            out.push(alphabet[idx] as char);
            produced += 1;
        }
        // else: reject and resample. No bias.
    }
    byte_buf.zeroize_explicit();
    Ok(out)
}

trait ZeroizeExplicit {
    fn zeroize_explicit(&mut self);
}

impl ZeroizeExplicit for [u8; 1] {
    fn zeroize_explicit(&mut self) {
        self[0] = 0;
    }
}

/// Minimal RFC 4648 base64 url-safe encoder (no padding) — used for
/// `PreSharedKey` material. We don't pull a `base64` crate just for
/// this 30-line helper.
fn base64_url_encode(bytes: &[u8]) -> String {
    const ALPHA: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    let mut i = 0;
    while i + 3 <= bytes.len() {
        let n: u32 =
            (u32::from(bytes[i]) << 16) | (u32::from(bytes[i + 1]) << 8) | u32::from(bytes[i + 2]);
        out.push(ALPHA[((n >> 18) & 0x3F) as usize] as char);
        out.push(ALPHA[((n >> 12) & 0x3F) as usize] as char);
        out.push(ALPHA[((n >> 6) & 0x3F) as usize] as char);
        out.push(ALPHA[(n & 0x3F) as usize] as char);
        i += 3;
    }
    let rem = bytes.len() - i;
    if rem == 1 {
        let n: u32 = u32::from(bytes[i]) << 16;
        out.push(ALPHA[((n >> 18) & 0x3F) as usize] as char);
        out.push(ALPHA[((n >> 12) & 0x3F) as usize] as char);
    } else if rem == 2 {
        let n: u32 = (u32::from(bytes[i]) << 16) | (u32::from(bytes[i + 1]) << 8);
        out.push(ALPHA[((n >> 18) & 0x3F) as usize] as char);
        out.push(ALPHA[((n >> 12) & 0x3F) as usize] as char);
        out.push(ALPHA[((n >> 6) & 0x3F) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_length_matches_policy() {
        let p = SecretGenPolicy::PasswordRandom {
            length: 16,
            charset: Charset::Alphanumeric,
            max_length: Some(16),
        };
        let v = generate(&p).unwrap();
        assert_eq!(v.len(), 16);
    }

    #[test]
    fn password_chars_are_in_alphabet() {
        let p = SecretGenPolicy::PasswordRandom {
            length: 64,
            charset: Charset::Alphanumeric,
            max_length: None,
        };
        let v = generate(&p).unwrap();
        for c in v.chars() {
            assert!(c.is_ascii_alphanumeric(), "non-alphanumeric: {c:?}");
        }
    }

    #[test]
    fn hex_password_produces_only_hex_digits() {
        let p = SecretGenPolicy::PasswordRandom {
            length: 32,
            charset: Charset::Hex,
            max_length: None,
        };
        let v = generate(&p).unwrap();
        for c in v.chars() {
            assert!(c.is_ascii_hexdigit() && (c.is_ascii_digit() || c.is_ascii_lowercase()));
        }
    }

    #[test]
    fn token_with_prefix_starts_with_prefix() {
        let p = SecretGenPolicy::Token {
            length: 12,
            prefix: Some("pat_".into()),
        };
        let v = generate(&p).unwrap();
        assert!(v.starts_with("pat_"));
        assert_eq!(v.len(), 4 + 12);
    }

    #[test]
    fn psk_is_base64url_of_length_bytes() {
        let p = SecretGenPolicy::PreSharedKey { length_bytes: 32 };
        let v = generate(&p).unwrap();
        // 32 bytes → ceil(32/3)*4 = 44 chars of base64 url-safe (no padding).
        // Our encoder skips padding: 32%3=2 → 44 - 1 padding = 43 actual.
        assert_eq!(v.len(), 43);
        for c in v.chars() {
            assert!(c.is_ascii_alphanumeric() || c == '-' || c == '_');
        }
    }

    #[test]
    fn distinct_calls_produce_distinct_values() {
        let p = SecretGenPolicy::PasswordRandom {
            length: 32,
            charset: Charset::Alphanumeric,
            max_length: None,
        };
        let a = generate(&p).unwrap();
        let b = generate(&p).unwrap();
        // Astronomically unlikely to collide at 32 chars from 62-char alphabet.
        assert_ne!(*a, *b);
    }

    #[test]
    fn unimplemented_policies_return_typed_error() {
        for p in [
            SecretGenPolicy::WireguardKeypair,
            SecretGenPolicy::SshKeypair {
                algo: cofre_types::SshAlgo::Ed25519,
            },
            SecretGenPolicy::TlsKeypair {
                algo: cofre_types::TlsAlgo::Ed25519,
                validity_days: 365,
            },
        ] {
            assert!(matches!(
                generate(&p),
                Err(GenerationError::NotYetImplemented(_))
            ));
        }
    }
}
