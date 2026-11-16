#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
set -eu

mkdir -p /run/sshd /run/krl-check
cd /run/krl-check
cp /fixture/subject-key /fixture/personal-key .
chmod 600 subject-key personal-key
cp /fixture/personal.pub authorized_keys
cp /fixture/trusted-ca.pub trusted-ca.pub
cp /fixture/principals principals
cp /fixture/empty.krl active.krl
ssh-keygen -q -t ed25519 -N '' -f host-key
printf '[127.0.0.1]:2222 %s\n' "$(cat host-key.pub)" > known_hosts
cat > sshd_config <<'CONFIG'
Port 2222
ListenAddress 127.0.0.1
HostKey /run/krl-check/host-key
PidFile /run/krl-check/sshd.pid
AuthorizedKeysFile /run/krl-check/authorized_keys
AuthorizedPrincipalsFile /run/krl-check/principals
TrustedUserCAKeys /run/krl-check/trusted-ca.pub
RevokedKeys /run/krl-check/active.krl
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
PermitRootLogin no
AllowUsers deploy
LogLevel ERROR
CONFIG
/usr/sbin/sshd -t -f sshd_config
/usr/sbin/sshd -D -e -f sshd_config > sshd.log 2>&1 &
server=$!
trap 'kill "$server" 2>/dev/null || true' EXIT HUP INT TERM

handshake() {
    identity=$1
    certificate=$2
    ssh -F /dev/null -p 2222 -i "$identity" \
        -o "CertificateFile=$certificate" -o IdentitiesOnly=yes \
        -o BatchMode=yes -o PasswordAuthentication=no \
        -o KbdInteractiveAuthentication=no -o PreferredAuthentications=publickey \
        -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/run/krl-check/known_hosts \
        -o GlobalKnownHostsFile=/dev/null -o ConnectionAttempts=1 -o ConnectTimeout=5 \
        deploy@127.0.0.1 true
}

# Wait only for this owned daemon; every acceptance check below is a new connection.
attempt=0
until handshake personal-key none > /dev/null 2>&1; do
    attempt=$((attempt + 1))
    test "$attempt" -lt 50 || { printf 'owned sshd did not become ready\n' >&2; exit 1; }
    kill -0 "$server"
    sleep 0.1
done
handshake subject-key /fixture/old-cert.pub
handshake subject-key /fixture/other-member-cert.pub
handshake subject-key /fixture/other-team-cert.pub
handshake personal-key none

# sshd reads RevokedKeys for each authentication. Validate the replacement before use.
cp /fixture/revoked.krl replacement.krl
cp replacement.krl active.krl
/usr/sbin/sshd -t -f sshd_config
set +e
handshake subject-key /fixture/old-cert.pub > /dev/null 2>&1
revoked_status=$?
set -e
test "$revoked_status" -eq 255 || { printf 'revoked certificate unexpectedly admitted\n' >&2; exit 1; }
handshake subject-key /fixture/fresh-cert.pub
handshake subject-key /fixture/other-member-cert.pub
handshake subject-key /fixture/other-team-cert.pub
handshake personal-key none
printf 'Verified revoked refusal, fresh same-key issuance, other member, other CA and Personal handshakes.\n'
