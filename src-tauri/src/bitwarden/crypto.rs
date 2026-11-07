//! Bitwarden's key derivation and cipher format.
//!
//! None of this is home-made crypto: it is Bitwarden's documented format,
//! assembled from standard primitives. The order in which they come together
//! is the entire content of this module.
//!
//! The master password yields the *master key* — 32 bytes that decrypt
//! nothing. It is used further in two ways:
//!
//! 1. The server gets `PBKDF2(master_key, salt = password, 1 round)` as the
//!    "master password hash". That is all it ever sees.
//! 2. Locally it is stretched to 64 bytes by HKDF (32 for AES, 32 for the
//!    HMAC) and with that decrypts the `key` field of the token response — the
//!    actual *user key*, which unlocks everything else.
//!
//! An organization's entries add one step: the user key decrypts the
//! account's private RSA key, which in turn decrypts the organization key —
//! and only that one the entries.
//!
//! What is deliberately missing here is format `1.` (AES-128 with HMAC): it
//! dates from before 2016 and is in no vault a current server delivers.
//! Refusing it is more honest than supporting it untested.

use std::num::NonZeroU32;

use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockDecryptMut, KeyIvInit};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ring::{digest, hkdf, hmac, pbkdf2};
use rsa::{Oaep, RsaPrivateKey};
use rust_i18n::t;

type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// How the master password becomes the master key. The server says so at
/// "prelogin", because it depends on the account and not on the app.
#[derive(Clone, Copy, Debug)]
pub enum Kdf {
    /// `kdf: 0`. 600,000 rounds today, 100,000 in the past — both occur.
    Pbkdf2 { iterations: u32 },
    /// `kdf: 1`. Memory in MiB, as the server states it.
    Argon2id {
        iterations: u32,
        memory_mib: u32,
        parallelism: u32,
    },
}

/// 32 bytes from the master password. Decrypts nothing — see the module header.
pub struct MasterKey([u8; 32]);

/// A symmetric key as Bitwarden uses it.
///
/// Normally 64 bytes: 32 for AES-256-CBC, 32 for the HMAC-SHA-256 over it. An
/// account from very old times has only the first 32 and thus ciphertexts
/// without a MAC; that is why the MAC half is optional and not simply assumed.
#[derive(Clone)]
pub struct SymmetricKey {
    enc: [u8; 32],
    mac: Option<[u8; 32]>,
}

/// Length as `hkdf::KeyType`, because ring sizes the output by the type.
struct Len(usize);

impl hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

impl MasterKey {
    /// Derives the master key. The salt is the sign-in address in lowercase —
    /// for Argon2id its SHA-256, because Argon2 requires a salt of a fixed
    /// minimum length.
    pub fn derive(password: &str, email: &str, kdf: Kdf) -> Result<Self, String> {
        let email = email.trim().to_lowercase();
        let mut out = [0u8; 32];

        match kdf {
            Kdf::Pbkdf2 { iterations } => {
                let rounds = NonZeroU32::new(iterations)
                    .ok_or_else(|| t!("vault.bw_zero_iterations").into_owned())?;
                pbkdf2::derive(
                    pbkdf2::PBKDF2_HMAC_SHA256,
                    rounds,
                    email.as_bytes(),
                    password.as_bytes(),
                    &mut out,
                );
            }
            Kdf::Argon2id {
                iterations,
                memory_mib,
                parallelism,
            } => {
                let salt = digest::digest(&digest::SHA256, email.as_bytes());
                let params = argon2::Params::new(
                    memory_mib.saturating_mul(1024),
                    iterations,
                    parallelism,
                    Some(32),
                )
                .map_err(|e| t!("vault.bw_bad_argon2_params", error = e).into_owned())?;
                argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
                    .hash_password_into(password.as_bytes(), salt.as_ref(), &mut out)
                    .map_err(|e| t!("vault.bw_argon2_failed", error = e).into_owned())?;
            }
        }

        Ok(Self(out))
    }

    /// What the server gets to see as the password: a single PBKDF2 round over
    /// the master key, with the password as salt. The password itself never
    /// leaves this device.
    pub fn password_hash(&self, password: &str) -> String {
        let mut out = [0u8; 32];
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            NonZeroU32::new(1).expect("1 is not zero"),
            password.as_bytes(),
            &self.0,
            &mut out,
        );
        B64.encode(out)
    }

    /// HKDF-Expand to twice 32 bytes: the key the `key` field of the token
    /// response is decrypted with.
    pub fn stretched(&self) -> SymmetricKey {
        let prk = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, &self.0);
        let mut enc = [0u8; 32];
        let mut mac = [0u8; 32];
        for (info, out) in [
            (&b"enc"[..], &mut enc as &mut [u8; 32]),
            (&b"mac"[..], &mut mac),
        ] {
            prk.expand(&[info], Len(32))
                .expect("32 bytes is within HKDF's output limit")
                .fill(out)
                .expect("the buffer is exactly the requested length");
        }
        SymmetricKey {
            enc,
            mac: Some(mac),
        }
    }
}

impl SymmetricKey {
    /// 64 bytes are split into an AES and a MAC half, 32 count entirely as an
    /// AES key without MAC.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        match bytes.len() {
            64 => {
                let mut enc = [0u8; 32];
                let mut mac = [0u8; 32];
                enc.copy_from_slice(&bytes[..32]);
                mac.copy_from_slice(&bytes[32..]);
                Ok(Self {
                    enc,
                    mac: Some(mac),
                })
            }
            32 => {
                let mut enc = [0u8; 32];
                enc.copy_from_slice(bytes);
                Ok(Self { enc, mac: None })
            }
            other => Err(t!("vault.bw_bad_key_length", length = other).into_owned()),
        }
    }
}

/// Which format a ciphertext has. The number comes before the dot.
#[derive(Clone, Copy, PartialEq, Debug)]
enum EncType {
    /// `0.iv|ct` — AES-256-CBC without MAC.
    AesCbc256,
    /// `2.iv|ct|mac` — the normal case.
    AesCbc256HmacSha256,
    /// `3.ct` / `4.ct` — RSA-2048-OAEP; the difference is the hash function.
    /// Organization keys come wrapped like this, nothing else.
    Rsa2048Oaep { sha256: bool },
}

/// A ciphertext in Bitwarden's text form, split up.
pub struct EncString {
    kind: EncType,
    iv: Vec<u8>,
    data: Vec<u8>,
    mac: Vec<u8>,
}

/// Names only shape and lengths. A ciphertext is encrypted, but it still does
/// not belong in an error message — and `Debug` ends up exactly there.
impl std::fmt::Debug for EncString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "EncString({:?}, {} bytes, mac {})",
            self.kind,
            self.data.len(),
            if self.mac.is_empty() {
                "none"
            } else {
                "present"
            }
        )
    }
}

impl EncString {
    /// Splits `"<type>.<part>|<part>|<part>"`.
    ///
    /// A value without any type marker is historically type 0; the form still
    /// occurs in old vaults and costs one line here.
    pub fn parse(raw: &str) -> Result<Self, String> {
        let digits =
            |s: &str| !s.is_empty() && s.len() <= 2 && s.bytes().all(|b| b.is_ascii_digit());
        let (kind, rest) = match raw.split_once('.') {
            Some((prefix, rest)) if digits(prefix) => {
                let kind = match prefix {
                    "0" => EncType::AesCbc256,
                    "2" => EncType::AesCbc256HmacSha256,
                    "3" | "5" => EncType::Rsa2048Oaep { sha256: true },
                    "4" | "6" => EncType::Rsa2048Oaep { sha256: false },
                    "1" => return Err(t!("vault.bw_aes128").into_owned()),
                    other => {
                        return Err(
                            t!("vault.bw_unknown_cipher_format", format = other).into_owned()
                        )
                    }
                };
                (kind, rest)
            }
            // No prefix: type 0 in its oldest notation.
            _ => (EncType::AesCbc256, raw),
        };

        let mut parts = rest.split('|');
        let mut next = || -> Result<Vec<u8>, String> {
            B64.decode(parts.next().unwrap_or(""))
                .map_err(|e| t!("vault.bw_bad_base64", error = e).into_owned())
        };

        // With RSA the ciphertext comes first and there is no IV; with AES the
        // IV comes first. A MAC with "5" and "6" is read but not checked: there
        // it only protects the transport of a key that RSA-OAEP already makes
        // unforgeable.
        let (iv, data) = match kind {
            EncType::Rsa2048Oaep { .. } => (Vec::new(), next()?),
            _ => (next()?, next()?),
        };
        let mac = next().unwrap_or_default();

        Ok(Self {
            kind,
            iv,
            data,
            mac,
        })
    }

    /// Decrypts with a symmetric key and checks the MAC first — in this order,
    /// so no padding oracle arises.
    pub fn decrypt(&self, key: &SymmetricKey) -> Result<Vec<u8>, String> {
        match self.kind {
            EncType::Rsa2048Oaep { .. } => Err(t!("vault.bw_needs_private_key").into_owned()),
            EncType::AesCbc256HmacSha256 => {
                let mac_key = key
                    .mac
                    .as_ref()
                    .ok_or_else(|| t!("vault.bw_no_mac_half").into_owned())?;
                let expected = {
                    let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, mac_key);
                    let mut ctx = hmac::Context::with_key(&hmac_key);
                    ctx.update(&self.iv);
                    ctx.update(&self.data);
                    ctx.sign()
                };
                if !same(expected.as_ref(), &self.mac) {
                    return Err(t!("vault.bw_integrity_failed").into_owned());
                }
                self.aes(&key.enc)
            }
            EncType::AesCbc256 => self.aes(&key.enc),
        }
    }

    /// Decrypts with the account's private RSA key. Only organization keys
    /// come wrapped like this.
    pub fn decrypt_rsa(&self, key: &RsaPrivateKey) -> Result<Vec<u8>, String> {
        let EncType::Rsa2048Oaep { sha256 } = self.kind else {
            return Err(t!("vault.bw_not_rsa").into_owned());
        };
        let padding = if sha256 {
            Oaep::new::<sha2::Sha256>()
        } else {
            Oaep::new::<sha1::Sha1>()
        };
        key.decrypt(padding, &self.data)
            .map_err(|e| t!("vault.bw_org_key_unwrap_failed", error = e).into_owned())
    }

    fn aes(&self, enc: &[u8; 32]) -> Result<Vec<u8>, String> {
        if self.iv.len() != 16 {
            return Err(t!("vault.bw_no_iv").into_owned());
        }
        Aes256CbcDec::new(enc.into(), self.iv.as_slice().into())
            .decrypt_padded_vec_mut::<Pkcs7>(&self.data)
            .map_err(|_| t!("vault.bw_decrypt_failed").into_owned())
    }
}

/// Decrypts a ciphertext to text. The normal case: everything in the vault
/// except the keys themselves is UTF-8.
pub fn decrypt_str(raw: &str, key: &SymmetricKey) -> Result<String, String> {
    let bytes = EncString::parse(raw)?.decrypt(key)?;
    String::from_utf8(bytes).map_err(|_| t!("vault.bw_not_text").into_owned())
}

/// Like [`decrypt_str`], but returns an empty string instead of an error for
/// a missing or empty value.
///
/// Meant for fields that simply need not exist — an entry without a note is
/// not a problem anyone wants to read about.
pub fn decrypt_optional(raw: Option<&str>, key: &SymmetricKey) -> String {
    match raw {
        Some(value) if !value.is_empty() => decrypt_str(value, key).unwrap_or_default(),
        _ => String::new(),
    }
}

/// Reads the account's private RSA key from its PKCS#8 DER form.
pub fn private_key(der: &[u8]) -> Result<RsaPrivateKey, String> {
    use rsa::pkcs8::DecodePrivateKey;
    RsaPrivateKey::from_pkcs8_der(der)
        .map_err(|e| t!("vault.bw_private_key_unreadable", error = e).into_owned())
}

/// Compares two MACs without stopping at the first differing byte.
///
/// A comparison that stops early reveals through its running time how much of
/// a guessed MAC is already right — and with that it can be guessed byte by
/// byte. Hence everything to the end here, and only then the answer.
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Base64 in the URL-safe alphabet without padding, for the `Auth-Email`
/// header.
pub fn b64_url(raw: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Key derivation -------------------------------------------------------
    //
    // The dangerous mistake here is silent: whoever swaps password and salt
    // gets 32 plausible bytes just the same and only notices when the server
    // refuses the sign-in — without saying why. Hence a published PBKDF2 vector
    // instead of a self-comparison.

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn pbkdf2_takes_the_password_as_secret_and_the_address_as_salt() {
        let key = MasterKey::derive("password", "salt", Kdf::Pbkdf2 { iterations: 1 })
            .expect("one round is a round");
        assert_eq!(
            hex(&key.0),
            "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
        );
    }

    #[test]
    fn the_address_is_trimmed_and_lowercased_before_it_salts() {
        let kdf = Kdf::Pbkdf2 { iterations: 2 };
        let plain = MasterKey::derive("hunter2", "name@company.de", kdf).expect("derives");
        let noisy = MasterKey::derive("hunter2", "  Name@Company.DE  ", kdf).expect("derives");
        assert_eq!(hex(&plain.0), hex(&noisy.0));
    }

    #[test]
    fn zero_iterations_is_refused_rather_than_silently_weakened() {
        assert!(MasterKey::derive("hunter2", "a@b.de", Kdf::Pbkdf2 { iterations: 0 }).is_err());
    }

    #[test]
    fn stretching_gives_two_different_halves() {
        let stretched = MasterKey::derive("hunter2", "a@b.de", Kdf::Pbkdf2 { iterations: 2 })
            .expect("derives")
            .stretched();
        assert_ne!(
            stretched.enc,
            stretched.mac.expect("stretching makes a MAC half")
        );
    }

    // ---- Ciphertexts -----------------------------------------------------------

    fn key() -> SymmetricKey {
        let mut bytes = [0u8; 64];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = index as u8;
        }
        SymmetricKey::from_bytes(&bytes).expect("64 bytes is a key")
    }

    /// Seals the way Bitwarden does: AES-256-CBC, then an HMAC over IV and
    /// ciphertext. Only for the tests — the app only ever decrypts.
    fn seal(key: &SymmetricKey, plaintext: &[u8]) -> String {
        use aes::cipher::BlockEncryptMut;
        type Enc = cbc::Encryptor<aes::Aes256>;

        let iv = [7u8; 16];
        let ciphertext =
            Enc::new(&key.enc.into(), &iv.into()).encrypt_padded_vec_mut::<Pkcs7>(plaintext);
        let mac = {
            let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, key.mac.as_ref().expect("has a MAC"));
            let mut ctx = hmac::Context::with_key(&hmac_key);
            ctx.update(&iv);
            ctx.update(&ciphertext);
            ctx.sign()
        };
        format!(
            "2.{}|{}|{}",
            B64.encode(iv),
            B64.encode(&ciphertext),
            B64.encode(mac.as_ref())
        )
    }

    #[test]
    fn a_sealed_value_comes_back_as_it_went_in() {
        let key = key();
        let sealed = seal(&key, "-----BEGIN OPENSSH PRIVATE KEY-----".as_bytes());
        assert_eq!(
            decrypt_str(&sealed, &key).expect("round trip"),
            "-----BEGIN OPENSSH PRIVATE KEY-----"
        );
    }

    #[test]
    fn a_tampered_value_is_refused_instead_of_decrypted() {
        let key = key();
        let sealed = seal(&key, "hunter2".as_bytes());

        // One byte of the ciphertext flipped: without a MAC check this would
        // produce garbage or a padding error — and that would be an oracle.
        let mut parts: Vec<String> = sealed.split('|').map(str::to_string).collect();
        let mut ciphertext = B64.decode(&parts[1]).expect("test data is base64");
        ciphertext[0] ^= 0x01;
        parts[1] = B64.encode(&ciphertext);

        let result = decrypt_str(&parts.join("|"), &key);
        assert!(result.is_err(), "a changed ciphertext must not decrypt");
    }

    #[test]
    fn a_truncated_mac_is_refused() {
        let key = key();
        let sealed = seal(&key, "hunter2".as_bytes());
        let cut = &sealed[..sealed.len() - 8];
        assert!(decrypt_str(cut, &key).is_err());
    }

    // ---- Parsing --------------------------------------------------------------

    #[test]
    fn the_type_prefix_decides_the_shape() {
        let two = EncString::parse("2.AAAA|BBBB|CCCC").expect("parses");
        assert_eq!(two.kind, EncType::AesCbc256HmacSha256);
        assert!(!two.mac.is_empty());

        let zero = EncString::parse("0.AAAA|BBBB").expect("parses");
        assert_eq!(zero.kind, EncType::AesCbc256);
        assert!(zero.mac.is_empty());

        // With RSA there is no IV, the ciphertext comes first.
        let four = EncString::parse("4.AAAA").expect("parses");
        assert_eq!(four.kind, EncType::Rsa2048Oaep { sha256: false });
        assert!(four.iv.is_empty());
        assert!(!four.data.is_empty());
    }

    #[test]
    fn a_value_without_a_prefix_is_read_as_the_oldest_format() {
        let legacy = EncString::parse("AAAAAAAAAAAAAAAAAAAAAA==|BBBB").expect("parses");
        assert_eq!(legacy.kind, EncType::AesCbc256);
    }

    #[test]
    fn aes_128_says_so_instead_of_failing_obscurely() {
        let message = EncString::parse("1.AAAA|BBBB|CCCC").expect_err("must be refused");
        assert!(message.contains("AES-128"), "{message}");
    }

    #[test]
    fn an_unreadable_value_is_an_error_and_not_an_empty_secret() {
        assert!(EncString::parse("2.not base64!|BBBB|CCCC").is_err());
        assert!(EncString::parse("9.AAAA").is_err());
    }

    #[test]
    fn a_missing_value_reads_as_empty_rather_than_failing() {
        assert_eq!(decrypt_optional(None, &key()), "");
        assert_eq!(decrypt_optional(Some(""), &key()), "");
    }

    // ---- Comparison -----------------------------------------------------------

    #[test]
    fn the_mac_comparison_answers_on_content_and_length() {
        assert!(same(b"abcd", b"abcd"));
        assert!(!same(b"abcd", b"abce"));
        assert!(!same(b"abcd", b"abc"));
        assert!(same(b"", b""));
    }
}
