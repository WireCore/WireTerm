//! Generating keys, converting them and getting them onto a server.
//!
//! Everything here ends in the same form: a private key in OpenSSH format,
//! without a passphrase, just as the "Enter key" field stores it — it is
//! encrypted there anyway, with the device key or the project key. Alongside
//! it the public key as a line for `authorized_keys`, and its fingerprint.
//!
//! What gets converted is what the login itself reads too: OpenSSH, PEM,
//! PKCS#8 and PuTTY's `.ppk`.

use rand_core::UnwrapErr;
use russh::keys::ssh_key::{LineEnding, PrivateKey, PublicKey};
use russh::keys::{decode_secret_key, Algorithm, HashAlg};
use rust_i18n::t;
use serde::Serialize;
use zeroize::Zeroizing;

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct KeyPair {
    /// OpenSSH, without a passphrase.
    pub private: String,
    /// One line for `authorized_keys`.
    pub public: String,
    /// `SHA256:…`, as `ssh-keygen -l` shows it.
    pub fingerprint: String,
}

fn pair(key: &PrivateKey) -> Result<KeyPair, String> {
    let private: Zeroizing<String> = key
        .to_openssh(LineEnding::LF)
        .map_err(|e| t!("ssh.key_write_failed", error = e).into_owned())?;
    let public = key
        .public_key()
        .to_openssh()
        .map_err(|e| t!("ssh.public_key_write_failed", error = e).into_owned())?;
    Ok(KeyPair {
        private: private.to_string(),
        public,
        fingerprint: key.public_key().fingerprint(HashAlg::Sha256).to_string(),
    })
}

/// A new key: `ed25519` or `rsa` (4096 bits, for servers that do not know
/// Ed25519 yet).
pub fn generate(kind: &str, comment: &str) -> Result<KeyPair, String> {
    let algorithm = match kind {
        "ed25519" => Algorithm::Ed25519,
        "rsa" => Algorithm::Rsa { hash: None },
        other => return Err(t!("ssh.unknown_key_type", kind = other).into_owned()),
    };
    let mut rng = UnwrapErr(getrandom::SysRng);
    let mut key = PrivateKey::random(&mut rng, algorithm)
        .map_err(|e| t!("ssh.key_generate_failed", error = e).into_owned())?;
    key.set_comment(comment.trim());
    pair(&key)
}

/// Reads a private key in one of the formats the login knows, and returns it
/// as OpenSSH without a passphrase.
pub fn convert(text: &str, passphrase: Option<&str>) -> Result<KeyPair, String> {
    let passphrase = passphrase.filter(|p| !p.is_empty());
    let key = decode_secret_key(text.trim(), passphrase).map_err(|e| {
        let message = e.to_string();
        if passphrase.is_none()
            && (message.contains("encrypted")
                || message.contains("passphrase")
                || message.contains("Encrypted"))
        {
            t!("ssh.key_needs_passphrase").into_owned()
        } else {
            t!("ssh.key_unreadable", error = e).into_owned()
        }
    })?;
    pair(&key)
}

/// The command that adds a line to `~/.ssh/authorized_keys` — unless the same
/// key is already in there, whatever its comment.
/// Prints `WIRETERM:ADDED` or `WIRETERM:PRESENT` at the end.
pub fn install_command(public: &str) -> Result<String, String> {
    let key = PublicKey::from_openssh(public.trim())
        .map_err(|_| t!("ssh.not_openssh_public_key").into_owned())?;
    // Written anew rather than taken over: that way nothing is in it that the
    // shell reads differently than intended.
    let line = key.to_openssh().map_err(|e| e.to_string())?;
    let body = line.splitn(3, ' ').take(2).collect::<Vec<_>>().join(" ");
    let quote = |text: &str| format!("'{}'", text.replace('\'', r"'\''"));
    Ok(format!(
        "umask 077; mkdir -p ~/.ssh && touch ~/.ssh/authorized_keys && \
         if grep -qF {body} ~/.ssh/authorized_keys; then echo WIRETERM:PRESENT; else \
         {{ tail -c1 ~/.ssh/authorized_keys | read -r _ || echo >> ~/.ssh/authorized_keys; }}; \
         printf '%s\\n' {line} >> ~/.ssh/authorized_keys && echo WIRETERM:ADDED; fi",
        body = quote(&body),
        line = quote(&line),
    ))
}

#[tauri::command]
pub async fn key_generate(kind: String, comment: String) -> Result<KeyPair, String> {
    // RSA with 4096 bits takes a while — not on the UI thread.
    tauri::async_runtime::spawn_blocking(move || generate(&kind, &comment))
        .await
        .map_err(|e| e.to_string())?
}

/// A private key from a file, a `.ppk` for instance.
#[tauri::command]
pub fn key_import(path: String, passphrase: Option<String>) -> Result<KeyPair, String> {
    let text = Zeroizing::new(
        std::fs::read_to_string(&path)
            .map_err(|e| t!("ssh.file_read_failed", path = path, error = e).into_owned())?,
    );
    let passphrase = passphrase.map(Zeroizing::new);
    convert(&text, passphrase.as_deref().map(String::as_str))
}

/// Public key and fingerprint for a key that was typed in.
#[tauri::command]
pub fn key_describe(private: String, passphrase: Option<String>) -> Result<KeyPair, String> {
    let private = Zeroizing::new(private);
    let passphrase = passphrase.map(Zeroizing::new);
    convert(&private, passphrase.as_deref().map(String::as_str))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_ed25519_key_makes_the_round_trip() {
        let new = generate("ed25519", "anna@wireterm").expect("generated");
        assert!(new
            .private
            .starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));
        assert!(new.public.starts_with("ssh-ed25519 AAAA"));
        assert!(new.public.ends_with(" anna@wireterm"));
        assert!(new.fingerprint.starts_with("SHA256:"));

        let again = convert(&new.private, None).expect("reads itself");
        assert_eq!(again.fingerprint, new.fingerprint);
        assert_ne!(
            generate("ed25519", "").expect("generated").fingerprint,
            new.fingerprint,
            "two keys are two keys"
        );
    }

    /// Two `.ppk` from `puttygen -t ed25519`, generated for this test only —
    /// once without, once with the passphrase "geheim".
    const PPK: &str = r"PuTTY-User-Key-File-3: ssh-ed25519
Encryption: none
Comment: wireterm-test
Public-Lines: 2
AAAAC3NzaC1lZDI1NTE5AAAAIIA7zkwsAYW7QH1DHEUXMqJj610DkWXFfsnQORP7
vFvW
Private-Lines: 1
AAAAIAFUIAT+wDdnavBhb3IyEZndSfK337OQOIcSgV2YZ0Jr
Private-MAC: 570b406a91773ddc1659ff50902f675ec406062456caa81629c89e0c6f826760
";
    const PPK_WITH: &str = r"PuTTY-User-Key-File-3: ssh-ed25519
Encryption: aes256-cbc
Comment: wireterm-test
Public-Lines: 2
AAAAC3NzaC1lZDI1NTE5AAAAIFKR5hKancGYHRoIsO83M5myjOEolHohXXzbW81U
XVlg
Key-Derivation: Argon2id
Argon2-Memory: 8192
Argon2-Passes: 13
Argon2-Parallelism: 1
Argon2-Salt: 61807c2e2bba226e302c567186b381dc
Private-Lines: 1
zXgUMwI9bqZ3+coHYkd7JLWUCJFsKGXbwCKCbs00dri8hjCLUBViYkTuo9tP3gXS
Private-MAC: 18db3c8574bb0757d268a0a6b8f9ab2a30e1c504731fb1d9b8f95fb3e7a5f09c
";
    const PPK_PUB: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIA7zkwsAYW7QH1DHEUXMqJj610DkWXFfsnQORP7vFvW wireterm-test";

    #[test]
    fn a_ppk_becomes_openssh() {
        let pair = convert(PPK, None).expect("reads the ppk");
        assert!(pair
            .private
            .starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));
        assert_eq!(pair.public, PPK_PUB, "the same public key as with puttygen");

        let error = convert(PPK_WITH, None).expect_err("without passphrase");
        assert!(error.contains("passphrase"), "{error}");
        let with = convert(PPK_WITH, Some("geheim")).expect("with passphrase");
        assert!(with.public.starts_with("ssh-ed25519 "));
    }

    #[test]
    fn a_passphrase_is_required_and_then_removed() {
        let mut rng = UnwrapErr(getrandom::SysRng);
        let key = PrivateKey::random(&mut rng, Algorithm::Ed25519).expect("generated");
        let encrypted = key
            .encrypt(&mut rng, "geheim")
            .expect("encrypted")
            .to_openssh(LineEnding::LF)
            .expect("writes");

        let error = convert(&encrypted, None).expect_err("without passphrase");
        assert!(error.contains("passphrase"), "{error}");

        let open = convert(&encrypted, Some("geheim")).expect("with passphrase");
        assert!(
            convert(&open.private, None).is_ok(),
            "without one afterwards"
        );
    }

    #[test]
    fn the_install_command_quotes_and_checks_only_the_key() {
        let new = generate("ed25519", "it's mine").expect("generated");
        let command = install_command(&new.public).expect("builds");
        let body = new
            .public
            .splitn(3, ' ')
            .take(2)
            .collect::<Vec<_>>()
            .join(" ");
        assert!(command.contains(&format!("grep -qF '{body}'")), "{command}");
        assert!(command.contains(r"it'\''s mine"), "{command}");
        assert!(install_command("rm -rf ~").is_err());
    }
}
