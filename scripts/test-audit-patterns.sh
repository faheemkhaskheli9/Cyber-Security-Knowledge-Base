#!/usr/bin/env bash
# Regression checks for the audit's deserialization detection expression.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
pattern="$(grep '^check "pickle/yaml.load unsafe deserialization"' "$ROOT/scripts/audit.sh" | sed -E "s/^[^']*'([^']*)'.*$/\1/")"
[ -n "$pattern" ] || { echo "missing deserialization scan"; exit 1; }
for sample in 'pickle.load(file)' 'pickle.loads(payload)' 'yaml.load(payload)' 'yaml.unsafe_load(payload)'; do
  printf '%s\n' "$sample" | grep -Eq "$pattern" || { echo "missed: $sample"; exit 1; }
done
for sample in 'yaml.safe_load(payload)' 'json.loads(payload)' 'pickle.dumps(payload)'; do
  if printf '%s\n' "$sample" | grep -Eq "$pattern"; then echo "false positive: $sample"; exit 1; fi
done
echo "[ok] deserialization audit patterns"
