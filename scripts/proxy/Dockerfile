# Two proxies for the test `proxy::tests::through_real_proxies`: Dante as
# SOCKS5 and tinyproxy as an HTTP CONNECT proxy, both with a login. They sit
# in the network from scripts/ssh-jump and reach `ziel` there, which cannot
# be reached from outside.
#
#   docker build -t wireterm-ssh-jump scripts/ssh-jump
#   docker build -t wireterm-proxy scripts/proxy
#   docker network create wireterm-jump
#   docker run -d --rm --name wireterm-ziel --hostname ziel --network wireterm-jump --network-alias ziel wireterm-ssh-jump
#   docker run -d --rm --name wireterm-web --network wireterm-jump --network-alias web nginx:alpine
#   docker run -d --rm --name wireterm-proxy --network wireterm-jump -p 21080:1080 -p 23128:8888 wireterm-proxy
#   cargo test --lib proxy::tests::through_real_proxies -- --ignored
#
# User `anna`, password `geheim` — throwaway values for containers that only
# run on this machine.
FROM debian:bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends dante-server tinyproxy \
 && rm -rf /var/lib/apt/lists/*

# Dante checks the login against the system's users.
RUN useradd -M -s /usr/sbin/nologin anna \
 && echo 'anna:geheim' | chpasswd

RUN printf '%s\n' \
    'logoutput: stderr' \
    'internal: 0.0.0.0 port = 1080' \
    'external: eth0' \
    'clientmethod: none' \
    'socksmethod: username' \
    'user.privileged: root' \
    'user.unprivileged: nobody' \
    'client pass { from: 0.0.0.0/0 to: 0.0.0.0/0 }' \
    'socks pass { from: 0.0.0.0/0 to: 0.0.0.0/0 command: connect }' \
    > /etc/danted.conf

# Without `ConnectPort`, CONNECT may go to any port; without `Allow`, any client may use it.
RUN printf '%s\n' \
    'User nobody' \
    'Group nogroup' \
    'Port 8888' \
    'Listen 0.0.0.0' \
    'Timeout 600' \
    'BasicAuth anna geheim' \
    > /etc/tinyproxy/tinyproxy.conf

EXPOSE 1080 8888
CMD ["sh", "-c", "tinyproxy -c /etc/tinyproxy/tinyproxy.conf && exec danted -f /etc/danted.conf"]
