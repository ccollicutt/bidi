#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p .dev-plugins
chmod 700 .dev-plugins
exec 9>.dev-plugins/setup.lock
flock 9
if [[ ! -f .dev-plugins/publisher.key ]]; then
  go run ./cmd/plugin-release -keygen .dev-plugins/publisher.key
fi
for plugin in status echo host-facts disk-usage service-health; do
  if [[ ! -f .dev-plugins/$plugin.json ]]; then
    if [[ "$plugin" == host-facts ]]; then
      gcc -O2 -Wall -Wextra -o ".dev-plugins/$plugin" examples/host-facts/main.c
    else
      go build -o ".dev-plugins/$plugin" "./examples/$plugin"
    fi
    go run ./cmd/plugin-release -key .dev-plugins/publisher.key \
      -manifest "examples/manifests/$plugin.json" -artifact ".dev-plugins/$plugin" \
      -out ".dev-plugins/$plugin.json"
  fi
done
python3 - <<'PY'
import json
from pathlib import Path
root = Path('.dev-plugins')
plugins = ['status', 'echo', 'host-facts', 'disk-usage', 'service-health']
permissions = json.loads(Path('permissions.json').read_text())
previous = json.loads((root / 'permissions.json').read_text()) if (root / 'permissions.json').exists() else {}
actions = ['status', 'echo', 'host-facts.snapshot', 'disk-usage.measure', 'service-health.check']
for agent in permissions:
    permissions[agent] = list(dict.fromkeys(permissions[agent] + previous.get(agent, []) + actions))
(root / 'permissions.json').write_text(json.dumps(permissions, indent=2) + '\n')
(root / 'publisher-keys.json').write_text(json.dumps({'operations-2026': (root / 'publisher.key.pub').read_text().strip()}, indent=2) + '\n')
if not (root / 'services.json').exists():
    (root / 'services.json').write_text(json.dumps({'local-http': {'address': '127.0.0.1:18080', 'path': '/'}}, indent=2) + '\n')
if (root / 'catalog.json').exists():
    catalog = json.loads((root / 'catalog.json').read_text())
else:
    catalog = {'releases': [{'manifest': p + '.json', 'artifact': p} for p in plugins], 'desired': {}, 'active': {}}
for agent in permissions:
    catalog['desired'].setdefault(agent, {p: '1.0.0' for p in plugins})
    catalog['active'].setdefault(agent, {p: '1.0.0' for p in plugins})
serialized = json.dumps(catalog, indent=2) + '\n'
if not (root / 'catalog.json').exists() or json.loads((root / 'catalog.json').read_text()) != catalog:
    tmp = root / 'catalog.json.tmp'
    tmp.write_text(serialized)
    tmp.replace(root / 'catalog.json')
PY
