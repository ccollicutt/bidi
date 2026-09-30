#!/usr/bin/env bash
set -euo pipefail

name=${1:-}
if [[ ! $name =~ ^[a-zA-Z][a-zA-Z0-9_-]*$ ]]; then
  echo 'usage: make agent NAME=agent-2 (letters, numbers, _ and - only)' >&2
  exit 1
fi

for file in certs/ca.crt certs/ca.key permissions.json; do
  if [[ ! -f $file ]]; then
    echo "missing $file; run make certs first" >&2
    exit 1
  fi
done

cert="certs/$name.crt"
key="certs/$name.key"
if [[ -e $cert || -e $key ]]; then
  echo "certificate or key already exists for $name; refusing to overwrite" >&2
  exit 1
fi

python3 - "$name" <<'PY'
import json
import sys

with open('permissions.json', encoding='utf-8') as source:
    permissions = json.load(source)
if not isinstance(permissions, dict):
    raise SystemExit('permissions.json must contain an object')
if sys.argv[1] in permissions:
    raise SystemExit(f'{sys.argv[1]} already exists in permissions.json')
PY

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
umask 077

openssl req -newkey rsa:2048 -noenc \
  -keyout "$work/agent.key" -out "$work/agent.csr" \
  -subj "/CN=$name" >/dev/null 2>&1
printf 'extendedKeyUsage=clientAuth\n' > "$work/agent.ext"
openssl x509 -req -in "$work/agent.csr" \
  -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial \
  -out "$work/agent.crt" -days 30 -sha256 \
  -extfile "$work/agent.ext" >/dev/null 2>&1

mv "$work/agent.key" "$key"
mv "$work/agent.crt" "$cert"

python3 - "$name" <<'PY'
import json
import os
import sys
import tempfile

path = 'permissions.json'
with open(path, encoding='utf-8') as source:
    permissions = json.load(source)
permissions[sys.argv[1]] = ['status', 'echo']
fd, temporary = tempfile.mkstemp(prefix='.permissions-', dir='.')
try:
    with os.fdopen(fd, 'w', encoding='utf-8') as output:
        json.dump(permissions, output, indent=2)
        output.write('\n')
    os.replace(temporary, path)
finally:
    if os.path.exists(temporary):
        os.unlink(temporary)
PY

echo "Created $cert and $key and authorized $name. Restart the server to load permissions."
echo "Start the client with: ./bin/bidi-client -name $name -cert $cert -key $key"
