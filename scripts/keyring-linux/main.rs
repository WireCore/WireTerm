//! Checks the Linux branch of the device key — see Dockerfile.

mod store;

use store::{Lookup, SystemKeyring};

fn main() {
    let expected = std::env::args().nth(1).expect("available or unavailable");
    let store = SystemKeyring::new("wireterm-linux-test");
    match expected.as_str() {
        "available" => {
            store.delete().expect("clean up");
            assert!(matches!(store.load(), Lookup::Missing), "{:?}", store.load());
            store.save(&[42u8; 32]).expect("store");
            match store.load() {
                Lookup::Found(key) => assert_eq!(*key, [42u8; 32]),
                other => panic!("{other:?}"),
            }
            store.delete().expect("clean up");
            println!("ok: Secret Service takes the key and gives it back");
        }
        "unavailable" => match store.load() {
            Lookup::Unavailable(reason) => {
                println!("ok: without Secret Service it reports itself as unavailable ({reason})")
            }
            other => panic!("expected \"unavailable\", got: {other:?}"),
        },
        other => panic!("unknown: {other}"),
    }
}
