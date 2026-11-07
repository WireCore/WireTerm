# An SSH server for the tests `ssh::tests::jump_*` — started twice: once as
# the jump host with a port to the outside, once as the target, which is only
# reachable in the Docker network.
#
#   docker build -t wireterm-ssh-jump scripts/ssh-jump
#   docker network create wireterm-jump
#   docker run -d --rm --name wireterm-ziel --hostname ziel --network wireterm-jump --network-alias ziel wireterm-ssh-jump
#   docker run -d --rm --name wireterm-bastion --hostname bastion --network wireterm-jump -p 2223:22 wireterm-ssh-jump
#   cargo test --lib ssh::tests::jump -- --ignored
#
# User `anna`, password `geheim` — throwaway values for containers that only
# run on this machine.
FROM debian:bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server openssh-client \
 && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash anna \
 && echo 'anna:geheim' | chpasswd \
 && mkdir -p /run/sshd

RUN printf '%s\n' \
    'PasswordAuthentication yes' \
    'AllowTcpForwarding yes' \
    'AllowAgentForwarding yes' \
    > /etc/ssh/sshd_config.d/jump.conf

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
