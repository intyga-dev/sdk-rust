//! Crate-private helpers for the offline-approval layer: JavaScript-compatible timestamps, the
//! base64 spellings the envelopes use, OS randomness, and private-file handling.
//!
//! Kept in one place so the on-disk layout and the wire formats are defined once — the other SDKs
//! read and write the same directories (docs/OFFLINE-APPROVAL-SDK.md, "Files").

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::alphabet;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig, URL_SAFE_NO_PAD};
use base64::engine::DecodePaddingMode;
use base64::Engine as _;

/// Directories that hold replay state or incident records are private by default.
pub(crate) const PRIVATE_DIR_MODE: u32 = 0o700;
/// Files that can prove an incident, or pin the key a bundle is verified against.
pub(crate) const PRIVATE_FILE_MODE: u32 = 0o600;

// ---------------------------------------------------------------------------------------------
// Time
// ---------------------------------------------------------------------------------------------

/// Milliseconds since the Unix epoch, negative before it.
pub(crate) fn unix_ms(t: SystemTime) -> i64 {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_millis()).unwrap_or(i64::MAX),
        Err(e) => -i64::try_from(e.duration().as_millis()).unwrap_or(i64::MAX),
    }
}

/// The inverse of [`unix_ms`].
pub(crate) fn system_time_from_ms(ms: i64) -> SystemTime {
    let magnitude = std::time::Duration::from_millis(ms.unsigned_abs());
    if ms >= 0 {
        UNIX_EPOCH + magnitude
    } else {
        UNIX_EPOCH - magnitude
    }
}

/// `as_of`, or the system clock.
pub(crate) fn now_ms(as_of: Option<SystemTime>) -> i64 {
    unix_ms(as_of.unwrap_or_else(SystemTime::now))
}

/// Format exactly as JavaScript's `Date.prototype.toISOString()`: UTC, three fractional digits, `Z`
/// (`2026-10-06T12:00:00.123Z`). The signed bytes carry these strings, so every port must agree.
pub(crate) fn iso_from_ms(ms: i64) -> String {
    let days = ms.div_euclid(86_400_000);
    let rem = ms.rem_euclid(86_400_000);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        year,
        month,
        day,
        rem / 3_600_000,
        (rem / 60_000) % 60,
        (rem / 1_000) % 60,
        rem % 1_000
    )
}

/// Howard Hinnant's `civil_from_days`: days since 1970-01-01 to (year, month, day).
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// Parse an RFC 3339 timestamp to Unix milliseconds (sub-millisecond digits truncated), or `None`.
///
/// The grammar is the one every verifier port applies to signed timestamps (DIV §6.2):
/// `YYYY-MM-DDTHH:MM:SS[.1-9 digits](Z|±HH:MM)`, uppercase `T` and `Z`, a date that exists, no leap
/// second. It is stricter than JavaScript's `Date.parse`, which also takes date-only and legacy
/// formats; every timestamp this layer reads was written by `toISOString()`, so nothing legitimate
/// is lost, and a timestamp that only a lenient parser reads is not one to make a trust decision on.
pub(crate) fn parse_rfc3339_ms(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    let digits = |from: usize, to: usize| -> Option<i64> {
        let part = b.get(from..to)?;
        if !part.iter().all(u8::is_ascii_digit) {
            return None;
        }
        std::str::from_utf8(part).ok()?.parse().ok()
    };
    if b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
    {
        return None;
    }
    let year = digits(0, 4)?;
    let month = digits(5, 7)?;
    let day = digits(8, 10)?;
    let hour = digits(11, 13)?;
    let min = digits(14, 16)?;
    let sec = digits(17, 19)?;
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return None,
    };
    if day < 1 || day > days_in_month || hour > 23 || min > 59 || sec > 59 {
        return None;
    }

    let mut rest = &b[19..];
    let mut millis = 0i64;
    if rest.first() == Some(&b'.') {
        let n = rest[1..].iter().take_while(|c| c.is_ascii_digit()).count();
        if n == 0 || n > 9 {
            return None;
        }
        // Milliseconds are the first three fraction digits, right-padded: ".1" is 100 ms, as in JS.
        for i in 0..3 {
            millis = millis * 10
                + rest
                    .get(1 + i)
                    .filter(|_| i < n)
                    .map_or(0, |c| i64::from(c - b'0'));
        }
        rest = &rest[1 + n..];
    }
    let offset_secs: i64 = if rest == b"Z" {
        0
    } else {
        if rest.len() != 6 || (rest[0] != b'+' && rest[0] != b'-') || rest[3] != b':' {
            return None;
        }
        let at = b.len() - 6;
        let off_hour = digits(at + 1, at + 3)?;
        let off_min = digits(at + 4, at + 6)?;
        if off_hour > 23 || off_min > 59 {
            return None;
        }
        let magnitude = off_hour * 3600 + off_min * 60;
        if rest[0] == b'-' {
            -magnitude
        } else {
            magnitude
        }
    };

    let y = year - i64::from(month <= 2);
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let secs = days * 86_400 + hour * 3_600 + min * 60 + sec - offset_secs;
    Some(secs * 1_000 + millis)
}

// ---------------------------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------------------------

/// base64url without padding, as the `DIV1:`/`SIG1:` envelopes and compact JWS use.
pub(crate) fn b64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Padding-agnostic, trailing-bit-tolerant decoding over the standard alphabet.
const LENIENT: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_padding_mode(DecodePaddingMode::RequireNone)
        .with_decode_allow_trailing_bits(true),
);

/// Decode base64 or base64url, padded or not — the lenient reading Node's `Buffer.from(s, "base64")`
/// gives the reference after it maps `-_` to `+/`. Used for the trust bundle's compact JWS, where
/// leniency costs nothing: the signature covers the ENCODED form, so a stray character fails it.
pub(crate) fn b64_decode_lenient(s: &str) -> Option<Vec<u8>> {
    let normalized: String = s
        .trim_end_matches('=')
        .chars()
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            c => c,
        })
        .collect();
    LENIENT.decode(normalized).ok()
}

/// Strict base64url, as the `DIV1:`/`SIG1:` envelopes require: `^[A-Za-z0-9_-]*={0,2}$`. A
/// character outside the alphabet — including standard base64's `+` and `/` — is refused, never
/// skipped, so a paste with stray text in it cannot decode to something other than what was sent.
pub(crate) fn b64url_decode_strict(s: &str) -> Option<Vec<u8>> {
    let body = s
        .strip_suffix("==")
        .or_else(|| s.strip_suffix('='))
        .unwrap_or(s);
    if !body
        .bytes()
        .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
    {
        return None;
    }
    URL_SAFE_NO_PAD_LENIENT.decode(body).ok()
}

const URL_SAFE_NO_PAD_LENIENT: GeneralPurpose = GeneralPurpose::new(
    &alphabet::URL_SAFE,
    GeneralPurposeConfig::new()
        .with_decode_padding_mode(DecodePaddingMode::RequireNone)
        .with_decode_allow_trailing_bits(true),
);

/// ECMAScript WhiteSpace and LineTerminator — the set `String.prototype.trim` removes: TAB, LF, VT,
/// FF, CR, SPACE, NBSP, every other `Zs` space, LS, PS and the BOM (U+FEFF). NOT U+0085, which Rust's
/// `char::is_whitespace` includes and JavaScript does not; and Rust's set lacks the BOM. The envelopes
/// are pasted between tools in every SDK language, so all of them must trim exactly the same way.
pub(crate) fn is_js_whitespace(c: char) -> bool {
    matches!(
        c,
        '\u{0009}'..='\u{000D}'
            | '\u{0020}'
            | '\u{00A0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200A}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202F}'
            | '\u{205F}'
            | '\u{3000}'
            | '\u{FEFF}'
    )
}

/// `String.prototype.trim`.
pub(crate) fn js_trim(s: &str) -> &str {
    s.trim_matches(is_js_whitespace)
}

/// Lowercase hex.
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------------------------------------
// Randomness
// ---------------------------------------------------------------------------------------------

/// `N` bytes from the operating system's CSPRNG.
pub(crate) fn random_bytes<const N: usize>() -> Result<[u8; N], String> {
    let mut buf = [0u8; N];
    getrandom::getrandom(&mut buf).map_err(|e| format!("the system random source failed: {e}"))?;
    Ok(buf)
}

/// A random (version 4) UUID, lowercase — the shape of JavaScript's `crypto.randomUUID()`.
pub(crate) fn random_uuid() -> Result<String, String> {
    let mut b = random_bytes::<16>()?;
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = hex(&b);
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    ))
}

// ---------------------------------------------------------------------------------------------
// Private files
// ---------------------------------------------------------------------------------------------

#[cfg(unix)]
fn repair_mode(target: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    // Best effort, as in the reference: a few network filesystems do not implement POSIX modes.
    let _ = fs::set_permissions(target, fs::Permissions::from_mode(mode));
}

#[cfg(not(unix))]
fn repair_mode(_target: &Path, _mode: u32) {}

#[cfg(unix)]
fn private_open_options(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(PRIVATE_FILE_MODE);
}

#[cfg(not(unix))]
fn private_open_options(_options: &mut OpenOptions) {}

/// Create (or repair) a private directory, refusing one that is a symlink or not a directory.
pub(crate) fn ensure_private_dir(dir: &Path) -> Result<(), String> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(PRIVATE_DIR_MODE);
    }
    builder
        .create(dir)
        .map_err(|e| format!("could not create {}: {e}", dir.display()))?;
    let meta = fs::symlink_metadata(dir)
        .map_err(|e| format!("could not inspect {}: {e}", dir.display()))?;
    if !meta.is_dir() || meta.file_type().is_symlink() {
        return Err(format!("refusing unsafe directory: {}", dir.display()));
    }
    repair_mode(dir, PRIVATE_DIR_MODE);
    Ok(())
}

fn parent_of(file: &Path) -> &Path {
    match file.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    }
}

/// Atomically replace a sensitive file through an exclusive, same-directory temporary file.
pub(crate) fn write_private_file(file: &Path, contents: &[u8]) -> Result<(), String> {
    let dir = parent_of(file);
    ensure_private_dir(dir)?;
    match fs::symlink_metadata(file) {
        Ok(meta) if meta.file_type().is_symlink() || !meta.is_file() => {
            return Err(format!("refusing unsafe file: {}", file.display()));
        }
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("could not inspect {}: {e}", file.display())),
    }
    let base = file
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let temp = dir.join(format!(
        ".{base}.{}.{}.tmp",
        std::process::id(),
        hex(&random_bytes::<16>()?)
    ));
    let written = (|| -> std::io::Result<()> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        private_open_options(&mut options);
        let mut handle = options.open(&temp)?;
        handle.write_all(contents)?;
        handle.sync_all()?;
        drop(handle);
        repair_mode(&temp, PRIVATE_FILE_MODE);
        fs::rename(&temp, file)?;
        repair_mode(file, PRIVATE_FILE_MODE);
        Ok(())
    })();
    // After a successful rename the temporary is gone and this is a harmless NotFound.
    let _ = fs::remove_file(&temp);
    written.map_err(|e| format!("could not write {}: {e}", file.display()))
}

/// Create a marker exactly once. `create_new` is `O_CREAT|O_EXCL`: atomic on POSIX and Windows, and
/// with `O_EXCL` the open fails on an existing symlink rather than following it, so two processes
/// racing the same name cannot both succeed and a planted link cannot redirect the write.
pub(crate) fn create_private_marker(file: &Path, contents: &str) -> bool {
    if ensure_private_dir(parent_of(file)).is_err() {
        return false;
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    private_open_options(&mut options);
    let Ok(mut handle) = options.open(file) else {
        return false;
    };
    if handle.write_all(contents.as_bytes()).is_err() {
        // The marker exists, so the nonce IS claimed; reporting failure keeps this fail-closed.
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = handle.set_permissions(fs::Permissions::from_mode(PRIVATE_FILE_MODE));
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_round_trips_like_to_iso_string() {
        for s in [
            "2026-10-06T12:00:00.123Z",
            "1970-01-01T00:00:00.000Z",
            "2000-02-29T23:59:59.999Z",
            "1969-12-31T23:59:59.999Z",
        ] {
            let ms = parse_rfc3339_ms(s).unwrap();
            assert_eq!(iso_from_ms(ms), s);
        }
        assert_eq!(parse_rfc3339_ms("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_rfc3339_ms("1970-01-01T00:00:00.1Z"), Some(100));
        assert_eq!(
            parse_rfc3339_ms("1970-01-01T00:00:00.123456789Z"),
            Some(123)
        );
        assert_eq!(parse_rfc3339_ms("1970-01-01T01:00:00+01:00"), Some(0));
        for bad in [
            "yesterday",
            "2026-02-30T00:00:00Z",
            "2026-10-06t12:00:00Z",
            "2026-10-06T12:00:60Z",
            "",
        ] {
            assert_eq!(parse_rfc3339_ms(bad), None, "{bad}");
        }
        assert_eq!(unix_ms(system_time_from_ms(-1_500)), -1_500);
    }

    #[test]
    fn uuid_has_the_v4_shape() {
        let id = random_uuid().unwrap();
        assert_eq!(id.len(), 36);
        assert_eq!(&id[14..15], "4");
        assert!(matches!(&id[19..20], "8" | "9" | "a" | "b"));
        assert_ne!(id, random_uuid().unwrap());
    }

    #[test]
    fn lenient_base64_takes_both_alphabets() {
        assert_eq!(
            b64_decode_lenient("-_8").unwrap(),
            b64_decode_lenient("+/8=").unwrap()
        );
        assert_eq!(b64_decode_lenient("%%%"), None);
    }

    #[test]
    fn trims_exactly_what_javascript_trims() {
        assert_eq!(
            js_trim("\u{feff} \t\n\r\u{000b}\u{000c}x\u{00a0}\u{3000}\u{2028}\u{2029}"),
            "x"
        );
        assert_eq!(js_trim("\u{2000}\u{200a}\u{202f}\u{205f}\u{1680}x"), "x");
        // U+0085 (NEL) is Unicode White_Space but not ECMAScript whitespace; U+200B is neither.
        assert_eq!(js_trim("\u{0085}x\u{0085}"), "\u{0085}x\u{0085}");
        assert_eq!(js_trim("\u{200b}x"), "\u{200b}x");
        assert_eq!(js_trim(" \u{feff} "), "");
    }

    #[test]
    fn strict_base64url_refuses_anything_outside_the_alphabet() {
        assert_eq!(b64url_decode_strict("bnVsbA").unwrap(), b"null");
        assert_eq!(b64url_decode_strict("bnVsbA==").unwrap(), b"null");
        assert_eq!(b64url_decode_strict("-_8").unwrap(), vec![0xfb, 0xff]);
        assert_eq!(b64url_decode_strict("").unwrap(), Vec::<u8>::new());
        for bad in ["+/8", "bnV!sbA", "bnVs bA", "bnVsbA===", "=bnVsbA", "%%%"] {
            assert_eq!(b64url_decode_strict(bad), None, "{bad}");
        }
    }
}
