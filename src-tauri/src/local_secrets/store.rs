//! Where the device key lives when the system has a keyring.
//!
//! Deliberately without Tauri and without the rest of the app: that way the
//! Linux branch can be tested in a container that builds nothing but this
//! module — see `scripts/keyring-linux`. For the same reason the reasons below
//! are plain English and not localized: `rust_i18n` is not available there.

use keyring::Entry;
use zeroize::Zeroizing;

/// 32 bytes that are overwritten when they go out of scope.
pub type DeviceKey = Zeroizing<[u8; 32]>;

/// The name the key is stored under in the keyring.
const ACCOUNT: &str = "device-key";

/// What the keyring says when asked for the key.
#[derive(Debug)]
pub enum Lookup {
    Found(DeviceKey),
    /// The keyring is there, the entry is not — first start, or someone
    /// deleted it.
    Missing,
    /// No keyring, or one that does not answer. The normal case on Linux
    /// without Secret Service.
    Unavailable(String),
}

/// The system keyring: Credential Manager, Keychain or Secret Service — which
/// one is decided by `keyring` at build time.
pub struct SystemKeyring {
    service: String,
}

impl SystemKeyring {
    /// `service` separates the installed program from the development build,
    /// just as `paths.rs` does for the data directory.
    pub fn new(service: &str) -> Self {
        Self {
            service: service.to_string(),
        }
    }

    fn entry(&self) -> Result<Entry, String> {
        Entry::new(&self.service, ACCOUNT).map_err(describe)
    }

    pub fn load(&self) -> Lookup {
        let entry = match self.entry() {
            Ok(entry) => entry,
            Err(reason) => return Lookup::Unavailable(reason),
        };
        match entry.get_secret() {
            Ok(bytes) => match <[u8; 32]>::try_from(bytes.as_slice()) {
                Ok(key) => Lookup::Found(Zeroizing::new(key)),
                // An entry under our name, but not ours. Do not overwrite it:
                // better to ask than to throw something away.
                Err(_) => Lookup::Unavailable(format!(
                    "the keyring entry \"{}\" does not have the expected length",
                    self.service
                )),
            },
            Err(keyring::Error::NoEntry) => Lookup::Missing,
            Err(error) => Lookup::Unavailable(describe(error)),
        }
    }

    pub fn save(&self, key: &[u8; 32]) -> Result<(), String> {
        self.entry()?.set_secret(key).map_err(describe)
    }

    /// Only for tests: removes the entry again.
    #[allow(dead_code)]
    pub fn delete(&self) -> Result<(), String> {
        match self.entry()?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(describe(error)),
        }
    }
}

fn describe(error: keyring::Error) -> String {
    match error {
        keyring::Error::NoDefaultStore => "no keyring available".to_string(),
        keyring::Error::NoStorageAccess(e) => {
            format!("the keyring denies access: {e}")
        }
        other => format!("keyring: {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Against this computer's real keyring. `#[ignore]`, because it creates
    /// an entry there — and deletes it again.
    ///
    /// On Linux the container from `scripts/keyring-linux` checks the same,
    /// with and without Secret Service.
    #[test]
    #[ignore]
    fn the_keyring_takes_the_key_and_gives_it_back() {
        let store = SystemKeyring::new("wireterm-test-keyring");
        store.delete().expect("clean up");
        assert!(
            matches!(store.load(), Lookup::Missing),
            "{:?}",
            store.load()
        );

        store.save(&[42u8; 32]).expect("store");
        match store.load() {
            Lookup::Found(key) => assert_eq!(*key, [42u8; 32]),
            other => panic!("{other:?}"),
        }

        store.delete().expect("clean up");
        assert!(matches!(store.load(), Lookup::Missing));
    }
}
