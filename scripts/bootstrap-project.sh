#!/usr/bin/env bash
# Install security baseline into a project. Usage: bootstrap-project.sh /path/to/project
# Safe to re-run: existing files are never overwritten.
set -eu
KB="$(cd "$(dirname "$0")/.." && pwd)"; T="${1:?project path required}"
[ -d "$T" ] || { echo "not a directory: $T" >&2; exit 1; }
mkdir -p "$T/.github/workflows" "$T/.claude/skills"

# put <src> <dst>: copy unless dst exists (portable replacement for `cp -n`, whose exit status
# and warnings differ between GNU coreutils versions and BSD).
put(){ if [ -e "$2" ]; then echo "[skip] $2 exists"; else cp -R "$1" "$2"; echo "[add] $2"; fi; }
put "$KB/templates/SECURITY.md" "$T/SECURITY.md"
put "$KB/templates/dependabot.yml" "$T/.github/dependabot.yml"
put "$KB/templates/codeql.yml" "$T/.github/workflows/codeql.yml"
put "$KB/templates/gitleaks.yml" "$T/.github/workflows/secret-scan.yml"
put "$KB/templates/pre-commit-config.yaml" "$T/.pre-commit-config.yaml"
put "$KB/.claude/skills/secure-project-audit" "$T/.claude/skills/secure-project-audit"

# Add each missing ignore entry on its own line (also when .gitignore lacks a trailing newline).
gi="$T/.gitignore"; touch "$gi"
[ -s "$gi" ] && [ -n "$(tail -c1 "$gi")" ] && printf '\n' >> "$gi"
for e in .env '*.pem' '*.key'; do grep -qxF -- "$e" "$gi" || { printf '%s\n' "$e" >> "$gi"; echo "[add] $e to .gitignore"; }; done

if ! grep -q 'cybersec-kb' "$T/CLAUDE.md" 2>/dev/null; then
  snippet=$(cat "$KB/templates/project-CLAUDE-security.md")
  printf '\n%s\n' "${snippet//'~/cybersec-kb'/$KB}" >> "$T/CLAUDE.md"; echo "[add] security import to CLAUDE.md"
fi
echo "Done. Edit SECURITY.md contact, CodeQL languages and Dependabot ecosystems; for an organization-owned repo"
echo "add a GITLEAKS_LICENSE secret (see secret-scan.yml). Then run: $KB/scripts/audit.sh $T"
