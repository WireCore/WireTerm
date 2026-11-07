# An SSH server with a second factor, only for the test `ssh::tests::two_factor_*`.
#
#   docker build -t wireterm-ssh-2fa scripts/ssh-2fa
#   docker run -d --rm --name wireterm-ssh-2fa -p 2222:22 wireterm-ssh-2fa
#   docker cp wireterm-ssh-2fa:/home/anna/.ssh/id_ed25519 <somewhere>
#
# User `anna`, password `geheim`, TOTP secret JBSWY3DPEHPK3PXP — all
# throwaway values for a container that only runs on this machine. The key
# is created at build time and is therefore nowhere in the repository.
FROM debian:bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server libpam-google-authenticator \
 && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash anna \
 && echo 'anna:geheim' | chpasswd \
 && mkdir -p /run/sshd /home/anna/.ssh \
 && ssh-keygen -q -t ed25519 -N '' -f /home/anna/.ssh/id_ed25519 -C wireterm-2fa-test \
 && cp /home/anna/.ssh/id_ed25519.pub /home/anna/.ssh/authorized_keys \
 && printf 'JBSWY3DPEHPK3PXP\n" WINDOW_SIZE 3\n" TOTP_AUTH\n' > /home/anna/.google_authenticator \
 && chown -R anna:anna /home/anna \
 && chmod 400 /home/anna/.google_authenticator \
 && chmod 600 /home/anna/.ssh/authorized_keys \
 # First the password (common-auth), then the code.
 && echo 'auth required pam_google_authenticator.so' >> /etc/pam.d/sshd

# Passwords only through keyboard-interactive, as on many servers; with a
# key, PAM still follows afterwards, i.e. password and code.
RUN printf '%s\n' \
    'PasswordAuthentication no' \
    'KbdInteractiveAuthentication yes' \
    'UsePAM yes' \
    'AuthenticationMethods publickey,keyboard-interactive keyboard-interactive' \
    > /etc/ssh/sshd_config.d/2fa.conf

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
