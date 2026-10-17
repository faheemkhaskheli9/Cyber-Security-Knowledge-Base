#!/usr/bin/env bash
# Lint the knowledge base: required section headings, internal links, README index coverage,
# line endings/encoding and GitHub Actions pins.
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

# Relative Markdown links and images ([text](../x.md), ![alt](docs/img.png)) must resolve from the linking file.
# Code spans and fenced blocks are skipped: they show link syntax, not links.
for f in README.md CONTRIBUTING.md CLAUDE.md SECURITY.md kb/*/*.md templates/*.md docs/*.md; do
  [ -f "$f" ] || continue
  dir=$(dirname "$f")
  # shellcheck disable=SC2016  # the backticks below are literal Markdown, not command substitution
  while IFS= read -r target; do
    t=${target%%#*}
    [ -n "$t" ] || continue
    case "$t" in http://*|https://*|mailto:*|/*) continue ;; esac
    [ -e "$dir/$t" ] || { echo "[x] $f: broken link '$target'"; fail=1; }
  done < <(awk '/^[[:space:]]*```/ { c = !c; next } !c' "$f" | sed 's/`[^`]*`//g' \
             | grep -oE '\]\([^)[:space:]]+' | sed 's/^](//' | sort -u)
done

# Every KB topic must be listed in the README index, so readers and agents can find it.
for f in kb/*/*.md; do
  grep -qF "]($f)" README.md || { echo "[x] README.md: KB index does not link $f"; fail=1; }
done

# Text files: LF line endings and valid UTF-8.
for f in README.md CONTRIBUTING.md CLAUDE.md SECURITY.md kb/*/*.md templates/* scripts/*.sh .github/*.yml .github/workflows/*.yml; do
  [ -f "$f" ] || continue
  if grep -q $'\r' "$f"; then echo "[x] $f: CRLF line endings"; fail=1; fi
  if command -v iconv >/dev/null && ! iconv -f UTF-8 -t UTF-8 "$f" >/dev/null 2>&1; then echo "[x] $f: not valid UTF-8"; fail=1; fi
done

# Actions in workflows and templates are pinned to full commit SHAs, and a template uses the same
# pin as this repo's own workflows (Dependabot updates .github/workflows only, not templates/).
pins=$(grep -hoE 'uses: *[^ ]+@[^ ]+' .github/workflows/*.yml templates/*.yml 2>/dev/null | sed -E 's/uses: *//' | sort -u)
while IFS= read -r u; do
  [ -n "$u" ] || continue
  case "$u" in ./*|docker://*) continue ;; esac
  [[ "${u#*@}" =~ ^[0-9a-f]{40}$ ]] || { echo "[x] action not pinned to a commit SHA: $u"; fail=1; }
done <<< "$pins"
for t in templates/*.yml; do
  while IFS= read -r u; do
    a=${u%@*}
    repo_pin=$(grep -hoE "uses: *$a@[0-9a-f]{40}" .github/workflows/*.yml | sed -E 's/.*@//' | sort -u | head -1)
    [ -z "$repo_pin" ] || [ "$repo_pin" = "${u#*@}" ] || { echo "[x] $t: $a pinned to ${u#*@}, .github/workflows uses $repo_pin"; fail=1; }
  done < <(grep -hoE 'uses: *[^ ]+@[0-9a-f]{40}' "$t" | sed -E 's/uses: *//' | sort -u)
done

if [ "$fail" -eq 0 ]; then echo "[ok] KB structure and links"; fi
exit "$fail"
