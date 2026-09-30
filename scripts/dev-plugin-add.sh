#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
plugin="${PLUGIN:-uptime}"
[[ "$plugin" =~ ^[a-z][a-z0-9-]*$ ]] || { echo 'Invalid plugin ID' >&2; exit 1; }
exec 9>.dev-plugins/setup.lock
flock 9
if [[ ! -f ".dev-plugins/$plugin.json" ]]; then
  go build -o ".dev-plugins/$plugin" "./examples/$plugin"
  ./bin/plugin-release -key .dev-plugins/publisher.key -manifest "examples/manifests/$plugin.json" \
    -artifact ".dev-plugins/$plugin" -out ".dev-plugins/$plugin.json"
fi
export PLUGIN="$plugin"
python3 - <<'PY'
import json, os
from pathlib import Path
root = Path('.dev-plugins')
p = os.environ['PLUGIN']
manifest = json.loads((root / (p + '.json')).read_text())
catalog = json.loads((root / 'catalog.json').read_text())
if not any(r['manifest'] == p + '.json' for r in catalog['releases']):
    catalog['releases'].append({'manifest': p + '.json', 'artifact': p})
permissions = json.loads((root / 'permissions.json').read_text())
for agent in permissions:
    permissions[agent] = list(dict.fromkeys(permissions[agent] + [a['name'] for a in manifest['actions']]))
    catalog['desired'].setdefault(agent, {})[p] = manifest['version']
    catalog['active'].setdefault(agent, {})[p] = manifest['version']
for name, value in [('catalog.json', catalog), ('permissions.json', permissions)]:
    tmp = root / (name + '.tmp')
    tmp.write_text(json.dumps(value, indent=2) + '\n')
    tmp.replace(root / name)
PY
./bin/bidi-control -operation reload
