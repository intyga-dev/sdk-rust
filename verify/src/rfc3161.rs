use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use crate::ledger::SignedAnchor;

const MAX_INPUT: usize = 1 << 20;
const MAX_ENCODED_TOKEN: usize = ((MAX_INPUT + 2) / 3) * 4;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Rfc3161Trust {
    #[serde(default)]
    pub ca_pem: String,
    #[serde(default)]
    pub signer_certificate_sha256: String,
    #[serde(default)]
    pub revocation: String,
    #[serde(default)]
    pub crl_pem: Option<String>,
    #[serde(default)]
    pub untrusted_pem: Option<String>,
    #[serde(default)]
    pub verification_time: Option<i64>,
    #[serde(default)]
    pub openssl_path: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Rfc3161Verification {
    pub ok: bool,
    pub reason: Option<String>,
    pub gen_time: Option<i64>,
}
fn failure() -> Rfc3161Verification {
    Rfc3161Verification {
        reason: Some("RFC 3161 verification failed".into()),
        ..Default::default()
    }
}

struct TempDir(PathBuf);
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn temp_dir() -> io::Result<TempDir> {
    for n in 0..32u32 {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let p =
            std::env::temp_dir().join(format!("intyga-rfc3161-{}-{stamp}-{n}", std::process::id()));
        match create_private_dir(&p) {
            Ok(()) => return Ok(TempDir(p)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "temporary directory collision",
    ))
}
#[cfg(unix)]
fn create_private_dir(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700).create(path)
}
#[cfg(not(unix))]
fn create_private_dir(path: &Path) -> io::Result<()> {
    // Non-Unix targets rely on the OS ACL inherited by the process; Unix modes do not exist there.
    fs::create_dir(path)
}

#[cfg(unix)]
fn create_private_file(path: &Path) -> io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}
#[cfg(not(unix))]
fn create_private_file(path: &Path) -> io::Result<fs::File> {
    // Non-Unix targets rely on the OS ACL inherited by the process; Unix modes do not exist there.
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

fn write_private(dir: &Path, name: &str, data: &[u8]) -> io::Result<PathBuf> {
    let p = dir.join(name);
    let mut file = create_private_file(&p)?;
    file.write_all(data)?;
    Ok(p)
}

fn run(path: &str, args: &[String], envs: &[(String, String)], cwd: &Path) -> bool {
    let mut cmd = Command::new(path);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .current_dir(cwd);
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let Ok(mut child) = cmd.spawn() else {
        return false;
    };
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(s)) => return s.success(),
            Ok(None) if start.elapsed() < Duration::from_secs(5) => {
                thread::sleep(Duration::from_millis(10))
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
        }
    }
}

pub fn verify_rfc3161_anchor(anchor: &SignedAnchor, trust: &Rfc3161Trust) -> Rfc3161Verification {
    let bad = failure();
    let Some(evidence) = anchor.evidence.as_ref() else {
        return bad;
    };
    let valid_hex = trust.signer_certificate_sha256.len() == 64
        && trust
            .signer_certificate_sha256
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c));
    let valid_algorithm = matches!(anchor.algorithm.as_str(), "ES256" | "Ed25519" | "RSA-PSS");
    // All seven signed fields, including the checkpoint position (DEWP §5.2).
    let valid_root = anchor.is_well_formed();
    if anchor.kind.as_deref() != Some("RFC3161")
        || evidence.len() > MAX_ENCODED_TOKEN
        || !valid_root
        || !valid_algorithm
        || trust.ca_pem.is_empty()
        || trust.ca_pem.len() > MAX_INPUT
        || !valid_hex
        || !matches!(trust.revocation.as_str(), "crl" | "unchecked")
        || trust.crl_pem.as_deref().unwrap_or("").len() > MAX_INPUT
        || trust.untrusted_pem.as_deref().unwrap_or("").len() > MAX_INPUT
        || (trust.revocation == "crl" && trust.crl_pem.as_deref().unwrap_or("").trim().is_empty())
    {
        return bad;
    }
    let Ok(token) = STANDARD.decode(evidence) else {
        return bad;
    };
    if STANDARD.encode(&token) != *evidence
        || token.is_empty()
        || token.len() > MAX_INPUT
        || !single_sequence(&token)
        || !valid_cms_signer_digest(&token)
    {
        return bad;
    }
    let now = trust.verification_time.unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64
            + 1
    });
    if !(0..=253_402_300_799).contains(&now) {
        return bad;
    }
    let Ok(tmp) = temp_dir() else { return bad };
    let dir = &tmp.0;
    let empty = dir.join("empty");
    if create_private_dir(&empty).is_err() {
        return bad;
    }
    let Ok(token_path) = write_private(dir, "token.der", &token) else {
        return bad;
    };
    let mut query = hex_decode("30360201013031300d060960864801650304020105000420");
    query.extend(anchor.digest());
    let Ok(query_path) = write_private(dir, "query.tsq", &query) else {
        return bad;
    };
    let trust_data = format!(
        "{}\n{}",
        trust.ca_pem,
        trust.crl_pem.as_deref().unwrap_or("")
    );
    let Ok(trust_path) = write_private(dir, "trust.pem", trust_data.as_bytes()) else {
        return bad;
    };
    let Ok(config) = write_private(
        dir,
        "openssl.cnf",
        b"# isolated Intyga verification config\n",
    ) else {
        return bad;
    };
    let signer = dir.join("signer.pem");
    let info = dir.join("info.der");
    let openssl_value = trust.openssl_path.as_deref().unwrap_or("openssl");
    let openssl_buf = if Path::new(openssl_value).is_relative()
        && openssl_value.contains(std::path::MAIN_SEPARATOR)
    {
        match std::env::current_dir() {
            Ok(cwd) => Some(cwd.join(openssl_value)),
            Err(_) => return bad,
        }
    } else {
        None
    };
    let openssl = openssl_buf
        .as_deref()
        .and_then(Path::to_str)
        .unwrap_or(openssl_value);
    let envs = vec![
        ("OPENSSL_CONF".into(), config.display().to_string()),
        (
            "SSL_CERT_FILE".into(),
            empty.join("cert.pem").display().to_string(),
        ),
        ("SSL_CERT_DIR".into(), empty.display().to_string()),
    ];
    let cms = vec![
        "cms".into(),
        "-verify".into(),
        "-binary".into(),
        "-inform".into(),
        "DER".into(),
        "-in".into(),
        s(&token_path),
        "-noverify".into(),
        "-signer".into(),
        s(&signer),
        "-out".into(),
        s(&info),
    ];
    if !run(openssl, &cms, &envs, dir) {
        return bad;
    }
    let Ok(pem) = fs::read(&signer) else {
        return bad;
    };
    if pem.len() > MAX_INPUT {
        return bad;
    };
    let Some(cert) = one_pem_cert(&pem) else {
        return bad;
    };
    if hex_encode(&Sha256::digest(&cert)) != trust.signer_certificate_sha256 {
        return bad;
    }
    let Ok(info_bytes) = fs::read(&info) else {
        return bad;
    };
    if info_bytes.len() > MAX_INPUT {
        return bad;
    };
    let Some((gen, fractional)) = parse_tst_info(&info_bytes) else {
        return bad;
    };
    if gen < 0 || gen > now || (fractional && now <= gen) {
        return bad;
    }
    let untrusted = if let Some(v) = trust.untrusted_pem.as_ref().filter(|v| !v.is_empty()) {
        match write_private(dir, "intermediates.pem", v.as_bytes()) {
            Ok(p) => Some(p),
            Err(_) => return bad,
        }
    } else {
        None
    };
    // `ts -verify` never loads OpenSSL's default trust locations; it trusts only what is passed. No
    // `-CAstore`: OpenSSL 3.0 loads a store URI eagerly and fails on an empty one (3.5 is lazy), which
    // made every valid token fail closed on Ubuntu 24.04's 3.0.13.
    let base = || {
        let mut a = vec![
            "ts".into(),
            "-verify".into(),
            "-token_in".into(),
            "-in".into(),
            s(&token_path),
            "-queryfile".into(),
            s(&query_path),
            "-CAfile".into(),
            s(&trust_path),
            "-CApath".into(),
            s(&empty),
        ];
        if let Some(p) = &untrusted {
            a.extend(["-untrusted".into(), s(p)])
        };
        a
    };
    let mut current = base();
    current.extend([
        "-attime".into(),
        now.to_string(),
        "-auth_level".into(),
        "2".into(),
        "-x509_strict".into(),
    ]);
    if trust.revocation == "crl" {
        current.push("-crl_check_all".into())
    }
    if !run(openssl, &current, &envs, dir) {
        return bad;
    };
    let mut issued = base();
    issued.extend([
        "-attime".into(),
        gen.to_string(),
        "-auth_level".into(),
        "2".into(),
        "-x509_strict".into(),
    ]);
    if !run(openssl, &issued, &envs, dir) {
        return bad;
    }
    Rfc3161Verification {
        ok: true,
        reason: None,
        gen_time: Some(gen),
    }
}
fn s(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}
fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn der_len(b: &[u8]) -> Option<(usize, usize)> {
    let x = *b.first()?;
    if x < 128 {
        return Some((x as usize, 1));
    }
    let n = (x & 127) as usize;
    if n == 0 || n > 4 || b.len() < n + 1 || b[1] == 0 {
        return None;
    }
    let mut v = 0usize;
    for x in &b[1..=n] {
        v = v.checked_mul(256)?.checked_add(*x as usize)?
    }
    if v < 128 {
        return None;
    }
    Some((v, n + 1))
}
fn single_sequence(b: &[u8]) -> bool {
    if b.first() != Some(&0x30) {
        return false;
    }
    der_len(&b[1..]).is_some_and(|(l, n)| 1 + n + l == b.len())
}
struct Reader<'a> {
    b: &'a [u8],
    o: usize,
}
impl<'a> Reader<'a> {
    fn item(&mut self, t: u8) -> Option<&'a [u8]> {
        if self.b.get(self.o) != Some(&t) {
            return None;
        }
        self.o += 1;
        let (l, n) = der_len(&self.b[self.o..])?;
        self.o += n;
        if l > self.b.len() - self.o {
            return None;
        }
        let v = &self.b[self.o..self.o + l];
        self.o += l;
        Some(v)
    }
    fn any_item(&mut self) -> Option<(u8, &'a [u8])> {
        let tag = *self.b.get(self.o)?;
        self.o += 1;
        let (l, n) = der_len(&self.b[self.o..])?;
        self.o += n;
        if l > self.b.len() - self.o {
            return None;
        }
        let v = &self.b[self.o..self.o + l];
        self.o += l;
        Some((tag, v))
    }
}

// Bounds the CMS profile to one SHA-2 digest in both SignedData's digestAlgorithms set and its
// sole SignerInfo. OpenSSL remains responsible for all cryptographic and certificate semantics.
fn valid_cms_signer_digest(b: &[u8]) -> bool {
    let Some(outer) = one_item(b, 0x30) else {
        return false;
    };
    let mut c = Reader { b: outer, o: 0 };
    if c.item(0x06) != Some(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 7, 2][..]) {
        return false;
    }
    let Some(explicit) = c.item(0xa0) else {
        return false;
    };
    if c.o != outer.len() {
        return false;
    }
    let Some(signed) = one_item(explicit, 0x30) else {
        return false;
    };
    let mut sd = Reader { b: signed, o: 0 };
    if sd.item(2).is_none() {
        return false;
    }
    let Some(set) = sd.item(0x31) else {
        return false;
    };
    let mut sr = Reader { b: set, o: 0 };
    let Some(set_alg) = cms_digest_algorithm(&mut sr) else {
        return false;
    };
    if sr.o != set.len() {
        return false;
    }
    if sd.item(0x30).is_none() {
        return false;
    }
    while matches!(sd.b.get(sd.o), Some(0xa0 | 0xa1)) {
        if sd.any_item().is_none() {
            return false;
        }
    }
    let Some(signers) = sd.item(0x31) else {
        return false;
    };
    if sd.o != signed.len() {
        return false;
    }
    let mut ss = Reader { b: signers, o: 0 };
    let Some(signer) = ss.item(0x30) else {
        return false;
    };
    if ss.o != signers.len() {
        return false;
    }
    let mut si = Reader { b: signer, o: 0 };
    if si.item(2).is_none() {
        return false;
    }
    let Some((sid, _)) = si.any_item() else {
        return false;
    };
    if sid != 0x30 && sid != 0x80 {
        return false;
    }
    let Some(signer_alg) = cms_digest_algorithm(&mut si) else {
        return false;
    };
    signer_alg == set_alg && si.o < signer.len()
}
fn one_item(b: &[u8], tag: u8) -> Option<&[u8]> {
    let mut r = Reader { b, o: 0 };
    let v = r.item(tag)?;
    if r.o == b.len() {
        Some(v)
    } else {
        None
    }
}
fn cms_digest_algorithm(r: &mut Reader<'_>) -> Option<u8> {
    let seq = r.item(0x30)?;
    let mut a = Reader { b: seq, o: 0 };
    let oid = a.item(0x06)?;
    let alg = match oid {
        [0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, 1] => 1,
        [0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, 2] => 2,
        [0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, 3] => 3,
        _ => return None,
    };
    if a.o < seq.len() && !a.item(0x05).is_some_and(|v| v.is_empty()) {
        return None;
    }
    if a.o == seq.len() {
        Some(alg)
    } else {
        None
    }
}
fn parse_tst_info(b: &[u8]) -> Option<(i64, bool)> {
    let mut r = Reader { b, o: 0 };
    let outer = r.item(0x30)?;
    if r.o != b.len() {
        return None;
    }
    let mut x = Reader { b: outer, o: 0 };
    if x.item(2)? != [1] {
        return None;
    }
    x.item(6)?;
    let imp = x.item(0x30)?;
    let mut i = Reader { b: imp, o: 0 };
    let alg = i.item(0x30)?;
    let mut a = Reader { b: alg, o: 0 };
    if a.item(6)? != [0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, 1] {
        return None;
    }
    i.item(4)?;
    if i.o != imp.len() {
        return None;
    }
    x.item(2)?;
    parse_time(std::str::from_utf8(x.item(0x18)?).ok()?)
}
fn parse_time(s: &str) -> Option<(i64, bool)> {
    let body = s.strip_suffix('Z')?;
    let (main, frac) = match body.split_once('.') {
        Some((m, f))
            if m.len() == 14
                && !f.is_empty()
                && !f.ends_with('0')
                && f.bytes().all(|c| c.is_ascii_digit()) =>
        {
            (m, true)
        }
        Some(_) => return None,
        None => (body, false),
    };
    if main.len() != 14 || !main.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let y = n(main, 0, 4)?;
    let mo = n(main, 4, 2)?;
    let d = n(main, 6, 2)?;
    let h = n(main, 8, 2)?;
    let mi = n(main, 10, 2)?;
    let se = n(main, 12, 2)?;
    if !(1..=12).contains(&mo) || h > 23 || mi > 59 || se > 59 {
        return None;
    }
    let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let md = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if d < 1 || d > md[(mo - 1) as usize] {
        return None;
    }
    let days = days_from_civil(y, mo, d);
    Some((days * 86400 + h * 3600 + mi * 60 + se, frac))
}
fn n(s: &str, o: usize, l: usize) -> Option<i64> {
    s.get(o..o + l)?.parse().ok()
}
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = y - if m <= 2 { 1 } else { 0 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yo = y - era * 400;
    let mp = m + if m > 2 { -3 } else { 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yo * 365 + yo / 4 - yo / 100 + doy;
    era * 146097 + doe - 719468
}
fn one_pem_cert(p: &[u8]) -> Option<Vec<u8>> {
    let s = std::str::from_utf8(p).ok()?.trim();
    let begin = "-----BEGIN CERTIFICATE-----";
    let end = "-----END CERTIFICATE-----";
    if s.matches(begin).count() != 1 || s.matches(end).count() != 1 {
        return None;
    }
    let a = s.strip_prefix(begin)?;
    let pos = a.find(end)?;
    if !a[pos + end.len()..].trim().is_empty() {
        return None;
    }
    let b64: String = a[..pos].lines().map(str::trim).collect();
    let der = STANDARD.decode(&b64).ok()?;
    if STANDARD.encode(&der) != b64 {
        return None;
    }
    Some(der)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::{verify_anchor_quorum, AnchorPolicy, AnchorQuorum, ExternalAnchorKeys};
    use std::collections::BTreeMap;

    #[derive(Deserialize)]
    struct Doc {
        cases: Vec<Case>,
    }
    #[derive(Deserialize)]
    struct Case {
        name: String,
        anchor: SignedAnchor,
        trust: Option<Rfc3161Trust>,
        expected: bool,
    }
    fn vectors() -> Doc {
        serde_json::from_str(include_str!(
            "../vectors/rfc3161-vectors.json"
        ))
        .unwrap()
    }

    #[test]
    fn shared_rfc3161_vectors() {
        for c in vectors().cases {
            assert_eq!(
                verify_rfc3161_anchor(&c.anchor, &c.trust.unwrap_or_default()).ok,
                c.expected,
                "{}",
                c.name
            );
        }
    }

    #[test]
    fn quorum_divergence_and_missing_executable() {
        let mut cases = vectors().cases;
        let valid = cases.remove(0);
        let different = cases.remove(0);
        let mut trusts = BTreeMap::new();
        trusts.insert(valid.anchor.issuer.clone(), valid.trust.clone().unwrap());
        let external = ExternalAnchorKeys {
            rfc3161: trusts,
            ..Default::default()
        };
        let policy = AnchorPolicy {
            required_anchors: 1,
            trusted_issuers: vec![valid.anchor.issuer.clone()],
            quorum: AnchorQuorum::NOfM,
            max_anchor_lag_seconds: None,
        };
        let resolver = |_: &SignedAnchor| None;
        let q = verify_anchor_quorum(
            std::slice::from_ref(&valid.anchor),
            &valid.anchor.daily_root,
            &policy,
            &resolver,
            &[],
            &external,
        );
        assert!(q.ok, "{q:?}");
        let q = verify_anchor_quorum(
            &[],
            &valid.anchor.daily_root,
            &policy,
            &resolver,
            std::slice::from_ref(&different.anchor),
            &external,
        );
        assert!(q.divergence, "{q:?}");
        let q = verify_anchor_quorum(
            std::slice::from_ref(&cases[0].anchor),
            &valid.anchor.daily_root,
            &policy,
            &resolver,
            &[],
            &external,
        );
        assert!(
            q.note
                .as_deref()
                .is_some_and(|n| n.contains("not verified")),
            "{q:?}"
        );
        let mut unavailable = valid.trust.unwrap();
        unavailable.openssl_path = Some("/definitely/missing/openssl".into());
        assert!(!verify_rfc3161_anchor(&valid.anchor, &unavailable).ok);
    }

    #[test]
    fn rejects_noncanonical_anchor_fields_and_pins_encoded_limit() {
        let valid = vectors().cases.remove(0);
        let trust = valid.trust.unwrap();
        let mut anchor = valid.anchor.clone();
        anchor.daily_root.replace_range(..1, "E");
        assert!(!verify_rfc3161_anchor(&anchor, &trust).ok);
        anchor = valid.anchor;
        anchor.algorithm = "SHA256".into();
        assert!(!verify_rfc3161_anchor(&anchor, &trust).ok);
        assert_eq!(MAX_ENCODED_TOKEN, 1_398_104);
    }
}
