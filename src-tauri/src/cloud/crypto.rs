//! Envelope encryption: what the server never gets to see.
//!
//! Two layers sit between a secret and a recipient, and the most common
//! mistake is to collapse them into one:
//!
//! ```text
//! secret       ──encrypted with──▶  project key PK  (32 bytes, one per project)
//! project key  ──wrapped with────▶  public key      (one per person)
//! ```
//!
//! The secret is encrypted **once**, no matter how many people may read it.
//! Only `PK` — 32 bytes — is wrapped once per person. If the secret were
//! encrypted directly with one's own public key, nobody but oneself could
//! ever read it.
//!
//! The sentence that matters: the server can *record* a share, but not
//! *grant* one. Only someone who already has `PK` can wrap it — that is, a
//! client. That is why this lives here and not there.
//!
//! The algorithms are stored as text in the database (`algorithm`,
//! `wrapAlgorithm`, `kdf`) so they can be changed later. What "v1" means is
//! in the constants below.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use ring::rand::{SecureRandom, SystemRandom};
use rust_i18n::t;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

/// The users' key pair.
pub const KEY_ALGORITHM: &str = "x25519";
/// What the private key is sealed with under the master password.
pub const WRAP_ALGORITHM: &str = "xchacha20poly1305";
/// How a password becomes a key.
pub const KDF: &str = "argon2id";
/// How a project key is wrapped for a recipient.
pub const GRANT_ALGORITHM: &str = "x25519-xchacha20poly1305";
/// What a secret is sealed with under the project key.
pub const SECRET_ALGORITHM: &str = "xchacha20poly1305";

/// Binds the result of the derivation to exactly this purpose. A change of
/// algorithm changes this string along with it, so that an old and a new key
/// are never the same.
const GRANT_INFO: &[u8] = b"wireterm/project-key/v1";

const NONCE_LEN: usize = 24;
const SALT_LEN: usize = 16;
const KEY_LEN: usize = 32;

/// The derivation parameters, as they travel along as a JSON string.
///
/// They travel **along** so they can be raised without locking out existing
/// accounts: signing in computes with what is in the row, never with a
/// constant hard-wired here. [`KdfParams::default`] therefore only applies to
/// new rows.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
pub struct KdfParams {
    /// Memory in KiB.
    pub m: u32,
    /// Iterations.
    pub t: u32,
    /// Lanes.
    pub p: u32,
}

impl Default for KdfParams {
    /// 64 MiB, 3 iterations, 4 lanes — the recommendation from `CLIENT.md`.
    fn default() -> Self {
        Self {
            m: 65536,
            t: 3,
            p: 4,
        }
    }
}

impl KdfParams {
    pub fn to_json(self) -> String {
        // A fixed set of three numbers; this cannot fail.
        serde_json::to_string(&self).unwrap_or_else(|_| r#"{"m":65536,"t":3,"p":4}"#.to_string())
    }

    /// What was in the row. An unreadable value is an error and no reason to
    /// carry on with the default: that would yield a different key, and the
    /// ciphertext would fail to open for no apparent reason.
    pub fn from_json(raw: &str) -> Result<Self, String> {
        serde_json::from_str(raw)
            .map_err(|e| t!("cloud_sync.kdf_params_unreadable", error = e).into_owned())
    }
}

/// 32 bytes that are overwritten when they go out of scope.
///
/// The private key and every project key go through this type so that no copy
/// stays behind in memory after they were needed — and so that they cannot be
/// accidentally written anywhere in the first place: `Zeroizing` is not
/// `Serialize`.
pub type Secret32 = Zeroizing<[u8; KEY_LEN]>;

pub fn random_bytes(len: usize) -> Result<Vec<u8>, String> {
    let mut buffer = vec![0u8; len];
    SystemRandom::new()
        .fill(&mut buffer)
        .map_err(|_| t!("cloud_sync.rng_unavailable").into_owned())?;
    Ok(buffer)
}

fn random_array<const N: usize>() -> Result<[u8; N], String> {
    let mut buffer = [0u8; N];
    SystemRandom::new()
        .fill(&mut buffer)
        .map_err(|_| t!("cloud_sync.rng_unavailable").into_owned())?;
    Ok(buffer)
}

/// A new project key. Generated in the client and stored nowhere — the only
/// thing of it that goes to the server is the wrapped version.
pub fn new_project_key() -> Result<Secret32, String> {
    Ok(Zeroizing::new(random_array::<KEY_LEN>()?))
}

pub fn new_nonce() -> Result<Vec<u8>, String> {
    random_bytes(NONCE_LEN)
}

pub fn new_salt() -> Result<Vec<u8>, String> {
    random_bytes(SALT_LEN)
}

// ---- Password -> key ---------------------------------------------------------

/// `masterKey = Argon2id(password, salt, params)`.
///
/// The same for the master password and for a recovery code: both wrap the
/// same private key, just under a different salt.
pub fn derive_key(password: &[u8], salt: &[u8], params: KdfParams) -> Result<Secret32, String> {
    let config = Params::new(params.m, params.t, params.p, Some(KEY_LEN))
        .map_err(|e| t!("cloud_sync.kdf_params_unusable", error = e).into_owned())?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, config);

    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(password, salt, out.as_mut())
        .map_err(|e| t!("cloud_sync.derivation_failed", error = e).into_owned())?;
    Ok(out)
}

// ---- XChaCha20Poly1305 -------------------------------------------------------

/// `aad` binds a ciphertext to its place. For a connection's secret that is the
/// `connectionId`: a tampered server then cannot move a ciphertext from one
/// connection to another without the check failing. The server does not store
/// the `aad` — it follows from the context the ciphertext is in.
pub fn seal(
    key: &[u8; KEY_LEN],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    if nonce.len() != NONCE_LEN {
        return Err(t!("cloud_sync.nonce_length", len = NONCE_LEN).into_owned());
    }
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| t!("cloud_sync.encryption_failed").into_owned())
}

/// Fails if the key does not match, the ciphertext was altered **or** the
/// `aad` is a different one. The three cannot be told apart from the outside,
/// and that is intentional: any answer about *why* it does not open would be
/// information for whoever is trying.
pub fn open(
    key: &[u8; KEY_LEN],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    if nonce.len() != NONCE_LEN {
        return Err(t!("cloud_sync.nonce_length", len = NONCE_LEN).into_owned());
    }
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| t!("cloud_sync.decryption_failed").into_owned())
}

// ---- The key pair ------------------------------------------------------------

/// A fresh X25519 pair. The private part never leaves this computer in
/// plaintext; the public part is what others need for wrapping.
pub struct KeyPair {
    pub private: Secret32,
    pub public: [u8; KEY_LEN],
}

pub fn new_key_pair() -> Result<KeyPair, String> {
    let bytes = random_array::<KEY_LEN>()?;
    let secret = StaticSecret::from(bytes);
    let public = PublicKey::from(&secret).to_bytes();
    Ok(KeyPair {
        private: Zeroizing::new(bytes),
        public,
    })
}

pub fn public_key_of(private: &[u8; KEY_LEN]) -> [u8; KEY_LEN] {
    PublicKey::from(&StaticSecret::from(*private)).to_bytes()
}

// ---- Wrapping the project key ------------------------------------------------

/// A wrapped version of `PK` for exactly one recipient.
pub struct Wrapped {
    pub ephemeral_public_key: [u8; KEY_LEN],
    pub nonce: Vec<u8>,
    pub wrapped_key: Vec<u8>,
}

/// Derives the key under which `PK` is sealed for a recipient.
///
/// `epk` and the recipient's key belong in the HKDF `info` so that the result
/// is bound to exactly these two parties: the same 32 bytes of Diffie-Hellman
/// yield a different key with other participants.
fn wrap_key(shared: &[u8], ephemeral_public: &[u8], recipient_public: &[u8]) -> Secret32 {
    let mut info = Vec::with_capacity(GRANT_INFO.len() + 2 * KEY_LEN);
    info.extend_from_slice(GRANT_INFO);
    info.extend_from_slice(ephemeral_public);
    info.extend_from_slice(recipient_public);

    let hkdf = Hkdf::<Sha256>::new(None, shared);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    // Only fails for an output length above 255 blocks; 32 bytes is one.
    let _ = hkdf.expand(&info, out.as_mut());
    out
}

/// Wraps `PK` for a recipient. One ephemeral pair per call — one's own private
/// key is not needed for this at all, which is why even someone who does not
/// know the recipient can do it.
pub fn wrap_project_key(
    project_key: &[u8; KEY_LEN],
    recipient_public: &[u8],
) -> Result<Wrapped, String> {
    let recipient: [u8; KEY_LEN] = recipient_public
        .try_into()
        .map_err(|_| t!("cloud_sync.recipient_key_length").into_owned())?;

    let mut ephemeral_bytes = random_array::<KEY_LEN>()?;
    let ephemeral = StaticSecret::from(ephemeral_bytes);
    let ephemeral_public = PublicKey::from(&ephemeral).to_bytes();

    let shared = ephemeral.diffie_hellman(&PublicKey::from(recipient));
    let key = wrap_key(shared.as_bytes(), &ephemeral_public, &recipient);

    let nonce = new_nonce()?;
    let wrapped_key = seal(&key, &nonce, project_key.as_ref(), &[])?;

    ephemeral_bytes.zeroize();

    Ok(Wrapped {
        ephemeral_public_key: ephemeral_public,
        nonce,
        wrapped_key,
    })
}

/// The same in reverse: one's own private key and the sender's ephemeral
/// public key yield the same Diffie-Hellman.
pub fn unwrap_project_key(
    private: &[u8; KEY_LEN],
    ephemeral_public: &[u8],
    nonce: &[u8],
    wrapped_key: &[u8],
) -> Result<Secret32, String> {
    let epk: [u8; KEY_LEN] = ephemeral_public
        .try_into()
        .map_err(|_| t!("cloud_sync.ephemeral_key_length").into_owned())?;

    let own_public = public_key_of(private);
    let secret = StaticSecret::from(*private);
    let shared = secret.diffie_hellman(&PublicKey::from(epk));
    let key = wrap_key(shared.as_bytes(), &epk, &own_public);

    let opened = open(&key, nonce, wrapped_key, &[])?;
    let bytes: [u8; KEY_LEN] = opened
        .as_slice()
        .try_into()
        .map_err(|_| t!("cloud_sync.unwrapped_key_length").into_owned())?;
    Ok(Zeroizing::new(bytes))
}

// ---- Recovery codes ----------------------------------------------------------

/// Crockford Base32 without I, L, O and U — the four characters that are easily
/// confused with 1, 1, 0 and V when copying by hand.
const ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// 6 groups of 4 characters, so 120 bits: `WT7K-4M2P-9XQD-R3FV-8HLN-2JWC`.
const GROUPS: usize = 6;
const GROUP_LEN: usize = 4;

/// A code as it is shown to the user — with hyphens.
pub fn new_recovery_code() -> Result<String, String> {
    let raw = random_bytes(GROUPS * GROUP_LEN)?;
    let chars: Vec<u8> = raw
        .iter()
        // Mapping a byte onto 32 characters skews the distribution by
        // 256/32 = 8 — that is, not at all: 32 divides 256 without remainder.
        .map(|byte| ALPHABET[(*byte % 32) as usize])
        .collect();

    let groups: Vec<String> = chars
        .chunks(GROUP_LEN)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect();
    Ok(groups.join("-"))
}

/// Upper case, no hyphens, no spaces — the way it has to look before
/// derivation. What someone types in rarely looks like that.
pub fn normalize_recovery_code(code: &str) -> String {
    code.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

/// The first group in plaintext — this is how the matching row is recognized,
/// instead of trying all eight Argon2id runs.
///
/// The code itself is stored nowhere, not even as a hash: a hash would be a
/// point of attack for exactly the database that is not supposed to be able to
/// read anything. The label gives away 20 of the 120 bits; the remaining 100
/// carry it.
pub fn recovery_label(code: &str) -> String {
    normalize_recovery_code(code)
        .chars()
        .take(GROUP_LEN)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The parameters travel along. If the other side computes with different
    /// ones, a different key comes out — and the ciphertext fails to open for
    /// no apparent reason. That is why this states that they actually count.
    #[test]
    fn different_parameters_yield_a_different_key() {
        // Kept small so the test does not touch 64 MiB per run.
        let fast = KdfParams { m: 64, t: 1, p: 1 };
        let other = KdfParams { m: 64, t: 2, p: 1 };

        let a = derive_key(b"hunter2", b"saltsaltsaltsalt", fast).expect("derives");
        let b = derive_key(b"hunter2", b"saltsaltsaltsalt", other).expect("derives");
        assert_ne!(a.as_ref(), b.as_ref());
    }

    #[test]
    fn the_same_parameters_yield_the_same_key() {
        let params = KdfParams { m: 64, t: 1, p: 1 };
        let a = derive_key(b"hunter2", b"saltsaltsaltsalt", params).expect("derives");
        let b = derive_key(b"hunter2", b"saltsaltsaltsalt", params).expect("derives");
        assert_eq!(a.as_ref(), b.as_ref());
    }

    #[test]
    fn kdf_params_travel_as_json_and_come_back() {
        let params = KdfParams::default();
        let json = params.to_json();
        assert_eq!(json, r#"{"m":65536,"t":3,"p":4}"#);
        assert_eq!(KdfParams::from_json(&json).expect("reads"), params);
    }

    /// The whole way: Anna wraps for Bert, Bert opens it.
    #[test]
    fn a_project_key_travels_from_one_person_to_another() {
        let bert = new_key_pair().expect("creates a pair");
        let pk = new_project_key().expect("creates a project key");

        let wrapped = wrap_project_key(&pk, &bert.public).expect("wraps");
        let back = unwrap_project_key(
            &bert.private,
            &wrapped.ephemeral_public_key,
            &wrapped.nonce,
            &wrapped.wrapped_key,
        )
        .expect("unwraps");

        assert_eq!(pk.as_ref(), back.as_ref());
    }

    /// Whoever does not have the private key cannot get at it — not even when
    /// they see everything else. The server sees everything else.
    #[test]
    fn someone_elses_private_key_opens_nothing() {
        let bert = new_key_pair().expect("creates a pair");
        let stranger = new_key_pair().expect("creates a pair");
        let pk = new_project_key().expect("creates a project key");

        let wrapped = wrap_project_key(&pk, &bert.public).expect("wraps");
        let attempt = unwrap_project_key(
            &stranger.private,
            &wrapped.ephemeral_public_key,
            &wrapped.nonce,
            &wrapped.wrapped_key,
        );
        assert!(attempt.is_err());
    }

    /// The `aad` binds a ciphertext to its connection. A server that moves it
    /// to another one gets caught doing so — that is the whole purpose of that
    /// one line.
    #[test]
    fn a_secret_belongs_to_its_connection() {
        let pk = new_project_key().expect("creates a project key");
        let nonce = new_nonce().expect("creates a nonce");

        let ciphertext = seal(&pk, &nonce, b"hunter2", b"conn-1").expect("encrypts");

        assert_eq!(
            open(&pk, &nonce, &ciphertext, b"conn-1").expect("opens"),
            b"hunter2"
        );
        assert!(open(&pk, &nonce, &ciphertext, b"conn-2").is_err());
    }

    #[test]
    fn a_code_has_six_groups_of_four_characters() {
        let code = new_recovery_code().expect("creates a code");
        let groups: Vec<&str> = code.split('-').collect();
        assert_eq!(groups.len(), GROUPS);
        assert!(groups.iter().all(|g| g.len() == GROUP_LEN));
        assert!(code.bytes().all(|b| b == b'-' || ALPHABET.contains(&b)));
    }

    /// A code is rarely copied exactly the way it is written.
    #[test]
    fn a_typed_in_code_becomes_the_same() {
        let typed = " wt7k 4m2p-9xqd R3FV-8hln-2jwc ";
        assert_eq!(normalize_recovery_code(typed), "WT7K4M2P9XQDR3FV8HLN2JWC");
        assert_eq!(recovery_label(typed), "WT7K");
    }
}
