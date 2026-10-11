//! Identifier helpers — CONTRACTS §6.3 (`urlSafeUsername` screenstate-manifest
//! key) and §4 (per-install device identity used by outbox rows, §6.1).

use rand::RngCore;

/// CE's `urlSafeUsername`: a URL-path-safe encoding of the account username.
///
/// The key appears verbatim in CE's screenstate manifest
/// (`capture-pipeline.md` §2: "`urlSafeUsername` (url-safe encoding of the
/// username)") and in the classifier spool vocabulary; the captured sample
/// `kckt0717` is alphanumeric and passes through unchanged (§6.3).
///
/// Encoding: every byte outside the RFC 3986 unreserved set
/// (`ALPHA / DIGIT / "-" / "." / "_" / "~"`) is percent-encoded as `%XX`
/// (uppercase hex) over the username's UTF-8 bytes. Unreserved-only usernames
/// are returned unchanged, so a plain CE-style account name round-trips.
pub fn url_safe_username(username: &str) -> String {
    let mut out = String::with_capacity(username.len());
    for &byte in username.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char)
            }
            _ => {
                const HEX: &[u8; 16] = b"0123456789ABCDEF";
                out.push('%');
                out.push(HEX[(byte >> 4) as usize] as char);
                out.push(HEX[(byte & 0x0f) as usize] as char);
            }
        }
    }
    out
}

/// Length in bytes of the device id (`new_device_id`).
pub const DEVICE_ID_LEN: usize = 16;

/// Generates a fresh device id: `DEVICE_ID_LEN` random bytes as lowercase
/// hex (32 characters). Used as the per-install identity carried by outbox
/// rows (`device_id` columns of §6.1) and settings records.
///
/// The id is random, not machine-derived — no hardware fingerprint is
/// collected (see the privacy model of §7).
pub fn new_device_id() -> String {
    let mut bytes = [0u8; DEVICE_ID_LEN];
    rand::thread_rng().fill_bytes(&mut bytes);
    to_hex(&bytes)
}

/// Whether `candidate` is a well-formed device id produced by
/// [`new_device_id`]: exactly `2 × DEVICE_ID_LEN` lowercase hex characters.
pub fn is_device_id(candidate: &str) -> bool {
    candidate.len() == DEVICE_ID_LEN * 2
        && candidate.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Lowercase hex encoding of a byte slice (no dependencies).
pub fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_safe_username_keeps_unreserved_names() {
        // Captured CE sample (classifier spool `su.dat`).
        assert_eq!(url_safe_username("kckt0717"), "kckt0717");
        assert_eq!(url_safe_username("Ann.User_2-1~x"), "Ann.User_2-1~x");
        assert_eq!(url_safe_username(""), "");
    }

    #[test]
    fn url_safe_username_encodes_reserved_bytes() {
        assert_eq!(url_safe_username("Ann User"), "Ann%20User");
        assert_eq!(url_safe_username("a/b"), "a%2Fb");
        assert_eq!(url_safe_username("50%"), "50%25");
        // "Ü" is UTF-8 C3 9C.
        assert_eq!(url_safe_username("Ü"), "%C3%9C");
        // Encoding is idempotent for already-unreserved output.
        assert_eq!(url_safe_username("Ann%20User"), "Ann%2520User");
    }

    #[test]
    fn device_ids_are_random_lowercase_hex() {
        let a = new_device_id();
        let b = new_device_id();
        assert!(is_device_id(&a), "{a}");
        assert!(is_device_id(&b), "{b}");
        assert_ne!(a, b, "two random ids must differ");

        assert!(!is_device_id(""));
        assert!(!is_device_id("abc"));
        assert!(!is_device_id(&"A".repeat(32)), "uppercase is rejected");
        assert!(!is_device_id(&"0".repeat(31)), "wrong length is rejected");
        assert!(is_device_id(&"0".repeat(32)), "all-digit ids are valid hex");
    }

    #[test]
    fn to_hex_is_lowercase() {
        assert_eq!(to_hex(&[0x00, 0x0f, 0xa5, 0xff]), "000fa5ff");
    }
}
