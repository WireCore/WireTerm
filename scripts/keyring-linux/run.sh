#!/bin/sh
set -e
echo "--- without Secret Service (server, WSL, lightweight window manager)"
env -u DBUS_SESSION_BUS_ADDRESS /test/target/release/keyring-linux unavailable
echo "--- with GNOME Keyring"
dbus-run-session -- sh -c '
  printf test | gnome-keyring-daemon --unlock --components=secrets >/dev/null
  /test/target/release/keyring-linux available
'
