#!/usr/bin/env bash
# Copy action pins (`uses: owner/action@sha # vX`) from .github/workflows/ into templates/*.yml.
# Dependabot only bumps .github/workflows/, so run this after merging an Action bump.
# Usage: scripts/sync-template-pins.sh [--check] [repo-root]
#   --check  report drift and exit 1 instead of rewriting the templates.
set -euo pipefail

check=0
if [ "${1:-}" = "--check" ]; then check=1; shift; fi
ROOT="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
cd "$ROOT"

drift=0
# action -> "sha # version" as pinned in the workflows (last one wins if they disagree).
declare -A pin
while IFS= read -r line; do
  ref=${line#*uses: }
  pin[${ref%%@*}]=${ref#*@}
done < <(grep -hoE 'uses: [^@ ]+@[0-9a-f]{40}( # [^ ]+)?' .github/workflows/*.yml)

for f in templates/*.yml; do
  while IFS= read -r line; do
    ref=${line#*uses: }
    action=${ref%%@*}
    want=${pin[$action]:-}
    [ -n "$want" ] && [ "${ref#*@}" != "$want" ] || continue
    drift=1
    if [ "$check" -eq 1 ]; then
      echo "[!] $f: $action@${ref#*@} differs from workflows ($want)"
    else
      sed -i "s|uses: $action@[0-9a-f]\{40\}\( # [^ ]*\)\?|uses: $action@$want|" "$f"
      echo "[fix] $f: $action -> $want"
    fi
  done < <(grep -oE 'uses: [^@ ]+@[0-9a-f]{40}( # [^ ]+)?' "$f" | sort -u)
done

if [ "$drift" -eq 0 ]; then echo "[ok] template action pins match workflows"; fi
[ "$check" -eq 1 ] && exit "$drift"
exit 0
