#!/usr/bin/env bash
# Quick local security audit. Usage: scripts/audit.sh [project-path]
set -u
P="${1:-.}"; cd "$P" || exit 1
issues=0
warn(){ echo "[!] $*"; issues=$((issues+1)); }
ok(){ echo "[ok] $*"; }

echo "== Secrets (pattern scan; values not printed) =="
pat='AKIA[0-9A-Z]{16}|-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----|ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{50,}|xox[baprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9]{32,}|AIza[0-9A-Za-z_-]{35}|(password|passwd|secret|api[_-]?key|token)[\"'"'"' ]*[:=][\"'"'"' ]*[A-Za-z0-9/+_-]{12,}'
hits=$(grep -rIlE "$pat" . --exclude-dir={.git,node_modules,venv,.venv,dist,build} 2>/dev/null | head -20)
if [ -n "$hits" ]; then warn "Possible secrets in:"; echo "$hits" | sed 's/^/    /'; else ok "no obvious secrets"; fi
git ls-files 2>/dev/null | grep -E '(^|/)(\.env|.*\.pem|id_rsa|.*\.p12|.*\.key)$' | grep -v example | sed 's/^/    tracked sensitive file: /' | { read -r l && warn "Sensitive files tracked by git" && echo "$l" && cat; } || true

echo "== Baseline files =="
[ -f SECURITY.md ] || [ -f .github/SECURITY.md ] && ok SECURITY.md || warn "missing SECURITY.md"
[ -f .github/dependabot.yml ] && ok dependabot || warn "missing .github/dependabot.yml"
ls .github/workflows 2>/dev/null | grep -qi codeql && ok CodeQL || warn "no CodeQL workflow"
grep -qE '^\.env' .gitignore 2>/dev/null && ok ".env ignored" || warn ".env not in .gitignore"

echo "== Risky code patterns =="
check(){ r=$(grep -rInE "$2" . --include='*.py' --include='*.js' --include='*.ts' --include='*.php' --include='*.java' --include='*.go' --include='*.rb' --exclude-dir={.git,node_modules,venv,.venv,dist,build} 2>/dev/null | head -5); [ -n "$r" ] && { warn "$1"; echo "$r" | sed 's/^/    /'; }; }
check "eval/exec on dynamic input" '(^|[^a-zA-Z_.])(eval|exec)\('
check "shell=True / os.system / child_process.exec" 'shell=True|os\.system\(|child_process.*exec\('
check "pickle/yaml.load unsafe deserialization" 'pickle\.loads?\(|yaml\.load\((?!.*Loader)'
check "weak hash MD5/SHA1" '(md5|sha1)\('
check "SQL string building" '(SELECT|INSERT|UPDATE|DELETE).*(\+|%s|\$\{|f")'
check "TLS verification disabled" 'verify=False|rejectUnauthorized: *false|InsecureSkipVerify'
check "innerHTML / dangerouslySetInnerHTML" 'innerHTML *=|dangerouslySetInnerHTML'
check "Math.random / random for security" 'Math\.random\(\)'

echo "== Docker / CI =="
[ -f Dockerfile ] && { grep -qE '^USER ' Dockerfile && ok "Docker non-root USER" || warn "Dockerfile runs as root"; grep -qE ':latest|^FROM [^:@ ]+$' Dockerfile && warn "Dockerfile unpinned base image"; }
for f in .github/workflows/*.y*ml; do [ -f "$f" ] || continue
  grep -q '^permissions:' "$f" || warn "$f: no top-level permissions block"
  grep -qE 'uses: [^@]+@(main|master|v[0-9]+)$' "$f" && warn "$f: actions not pinned to SHA (consider)"
  grep -q 'pull_request_target' "$f" && warn "$f: uses pull_request_target (review carefully)"
done

echo "== Dependency scanners (if installed) =="
[ -f package.json ] && command -v npm >/dev/null && npm audit --omit=dev 2>&1 | tail -5
[ -f requirements.txt ] && command -v pip-audit >/dev/null && pip-audit -r requirements.txt 2>&1 | tail -5
command -v trivy >/dev/null && trivy fs --quiet --severity HIGH,CRITICAL . 2>&1 | tail -15
command -v gitleaks >/dev/null && gitleaks detect --no-banner -q || true

echo; echo "Findings: $issues (heuristic; manual review still required)"
exit 0
