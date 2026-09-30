#!/usr/bin/env bash
set -euo pipefail
mkdir -p certs
if [[ -e certs/ca.key ]]; then
  echo 'certs/ca.key already exists; refusing to overwrite the development CA' >&2
  exit 1
fi
openssl req -x509 -newkey rsa:3072 -noenc -days 30 -sha256 \
  -keyout certs/ca.key -out certs/ca.crt -subj '/CN=bidi-dev-ca' \
  -addext 'basicConstraints=critical,CA:TRUE' >/dev/null 2>&1
openssl req -newkey rsa:2048 -noenc -keyout certs/server.key -out certs/server.csr \
  -subj '/CN=localhost' >/dev/null 2>&1
cat > certs/server.ext <<'EXT'
subjectAltName=DNS:localhost,IP:127.0.0.1
extendedKeyUsage=serverAuth
EXT
openssl x509 -req -in certs/server.csr -CA certs/ca.crt -CAkey certs/ca.key \
  -CAcreateserial -out certs/server.crt -days 30 -sha256 -extfile certs/server.ext >/dev/null 2>&1
openssl req -newkey rsa:2048 -noenc -keyout certs/agent.key -out certs/agent.csr \
  -subj '/CN=agent-1' >/dev/null 2>&1
cat > certs/agent.ext <<'EXT'
extendedKeyUsage=clientAuth
EXT
openssl x509 -req -in certs/agent.csr -CA certs/ca.crt -CAkey certs/ca.key \
  -CAcreateserial -out certs/agent.crt -days 30 -sha256 -extfile certs/agent.ext >/dev/null 2>&1
rm certs/*.csr certs/*.ext certs/*.srl
chmod 600 certs/*.key
if [[ ! -e permissions.json ]]; then
  cp permissions.example.json permissions.json
fi
echo 'Created development certificates in certs/'
