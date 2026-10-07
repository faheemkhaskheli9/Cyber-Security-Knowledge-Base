#!/usr/bin/env bash
# Install security baseline into a project. Usage: bootstrap-project.sh /path/to/project
set -eu
KB="$(cd "$(dirname "$0")/.." && pwd)"; T="${1:?project path required}"
mkdir -p "$T/.github/workflows" "$T/.claude/skills"
cp -n "$KB/templates/SECURITY.md" "$T/SECURITY.md" || true
cp -n "$KB/templates/dependabot.yml" "$T/.github/dependabot.yml" || true
cp -n "$KB/templates/codeql.yml" "$T/.github/workflows/codeql.yml" || true
cp -n "$KB/templates/gitleaks.yml" "$T/.github/workflows/secret-scan.yml" || true
cp -n "$KB/templates/pre-commit-config.yaml" "$T/.pre-commit-config.yaml" || true
cp -rn "$KB/.claude/skills/secure-project-audit" "$T/.claude/skills/"
grep -qxF '.env' "$T/.gitignore" 2>/dev/null || printf '.env\n*.pem\n*.key\n' >> "$T/.gitignore"
if ! grep -q 'cybersec-kb' "$T/CLAUDE.md" 2>/dev/null; then
  printf '\n' >> "$T/CLAUDE.md"; sed "s#~/cybersec-kb#$KB#" "$KB/templates/project-CLAUDE-security.md" >> "$T/CLAUDE.md"
fi
echo "Installed. Edit SECURITY.md contact + CodeQL language, then run: $KB/scripts/audit.sh $T"
