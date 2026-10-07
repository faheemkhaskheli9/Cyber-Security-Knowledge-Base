#!/usr/bin/env bash
# Lint the knowledge base: required section headings and internal links.
# Usage: scripts/check-kb.sh [repo-root]
set -euo pipefail

ROOT="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
cd "$ROOT"

# Reference files that are lists, not topic write-ups.
EXEMPT_STRUCTURE="kb/11-reference/glossary.md kb/11-reference/tools-and-cheatsheets.md"
REQUIRED=("## What" "## Why it matters" "## Attacks" "## Defenses" "## How to verify" "## References")

fail=0

for f in kb/*/*.md; do
  case " $EXEMPT_STRUCTURE " in *" $f "*) continue ;; esac
  prev=0
  for h in "${REQUIRED[@]}"; do
    line=$(grep -n -m1 -x -- "$h" "$f" | cut -d: -f1 || true)
    if [ -z "$line" ]; then
      echo "[x] $f: missing heading '$h'"; fail=1
    elif [ "$line" -lt "$prev" ]; then
      echo "[x] $f: heading '$h' out of order"; fail=1
    else
      prev=$line
    fi
  done
done

# Every topic must cite at least one external source in its References section.
for f in kb/*/*.md; do
  case " $EXEMPT_STRUCTURE " in *" $f "*) continue ;; esac
  sed -n '/^## References/,$p' "$f" | grep -qE 'https?://' || { echo "[x] $f: References has no http(s) source link"; fail=1; }
done

# Repo-relative references like `kb/..../x.md`, `templates/x`, `scripts/x` and markdown links must exist.
for f in README.md CONTRIBUTING.md CLAUDE.md kb/*/*.md; do
  while IFS= read -r ref; do
    [ -e "$ref" ] || { echo "[x] $f: broken reference '$ref'"; fail=1; }
  done < <(grep -oE '(^|[^A-Za-z0-9_./~-])(kb|templates|scripts)/[A-Za-z0-9._/-]+\.(md|sh|yml|yaml)' "$f" \
             | sed -E 's#^[^kts]##' | sort -u)
done

if [ "$fail" -eq 0 ]; then echo "[ok] KB structure and links"; fi
exit "$fail"
