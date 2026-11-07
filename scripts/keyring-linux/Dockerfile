# The Linux branch of the device key, without the rest of the app.
#
# It is built from the repository's root directory, because the module itself
# is copied in:
#
#   docker build -f scripts/keyring-linux/Dockerfile -t wireterm-keyring-linux .
#   docker run --rm wireterm-keyring-linux
#
# Two things are checked: without Secret Service the keyring reports itself
# as unavailable (the app then asks for an app password), with GNOME Keyring
# it takes the key and gives it back.
FROM rust:1-bookworm

RUN apt-get update \
 && apt-get install -y --no-install-recommends dbus dbus-x11 gnome-keyring \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /test
COPY scripts/keyring-linux/Cargo.toml ./
COPY scripts/keyring-linux/main.rs src/main.rs
COPY src-tauri/src/local_secrets/store.rs src/store.rs
RUN cargo build --release

COPY scripts/keyring-linux/run.sh /run.sh
RUN chmod +x /run.sh
CMD ["/run.sh"]
