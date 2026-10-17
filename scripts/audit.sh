#!/usr/bin/env bash
# Quick local security audit. Usage: scripts/audit.sh [--strict] [project-path]
# --strict: exit 1 when any finding is reported (for CI gates). Default: always exit 0.
set -u
STRICT=0
if [ "${1:-}" = "--strict" ]; then STRICT=1; shift; fi
P="${1:-.}"; cd "$P" || exit 2
issues=0
warn(){ echo "[!] $*"; issues=$((issues+1)); }
ok(){ echo "[ok] $*"; }
indent(){ sed 's/^/    /'; }
EXCLUDES=(--exclude-dir={.git,node_modules,venv,.venv,dist,build,vendor,target,__pycache__,.tox})

echo "== Secrets (pattern scan; values not printed) =="
# Provider token formats are case-sensitive; generic "key = value" assignments are matched case-insensitively
# so that SECRET_KEY=..., API_KEY: ... and Password = ... are all caught; a value followed by "(" or "."
# is a function call or attribute access (token = get_token()), not a literal.
pat_tokens='AKIA[0-9A-Z]{16}|-----BEGIN (RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----|gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{50,}|glpat-[A-Za-z0-9_-]{20}|xox[baprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9_-]{32,}|sk_live_[A-Za-z0-9]{24,}|AIza[0-9A-Za-z_-]{35}'
pat_generic='(password|passwd|secret|api[_-]?key|access[_-]?key|token)[A-Za-z0-9_]*["'"'"' ]*[:=][ ]*["'"'"']?[A-Za-z0-9/+_-]{12,}([^A-Za-z0-9/+_.(-]|$)'
# A line carrying a `gitleaks:allow` comment is treated as a reviewed false positive, as gitleaks does.
hits=$( { grep -rInE "$pat_tokens" . "${EXCLUDES[@]}" 2>/dev/null; grep -rIniE "$pat_generic" . "${EXCLUDES[@]}" 2>/dev/null; } \
        | grep -v 'gitleaks:allow' | cut -d: -f1 | sort -u | head -20)
if [ -n "$hits" ]; then warn "Possible secrets in:"; echo "$hits" | indent; else ok "no obvious secrets"; fi
tracked=$(git ls-files 2>/dev/null | grep -E '(^|/)(\.env(\..+)?|.*\.pem|id_rsa|id_ed25519|.*\.p12|.*\.pfx|.*\.key)$' | grep -viE 'example|sample|template' || true)
if [ -n "$tracked" ]; then warn "Sensitive files tracked by git (rotate anything real, then remove):"; echo "$tracked" | indent; fi

echo "== Baseline files =="
if [ -f SECURITY.md ] || [ -f .github/SECURITY.md ] || [ -f docs/SECURITY.md ]; then ok SECURITY.md; else warn "missing SECURITY.md"; fi
if [ -f .github/dependabot.yml ] || [ -f .github/dependabot.yaml ] || [ -f renovate.json ] || [ -f .github/renovate.json ]; then ok "dependency update bot"; else warn "missing .github/dependabot.yml (or Renovate config)"; fi
codeql=0; for f in .github/workflows/*.y*ml; do [ -f "$f" ] && grep -qi 'codeql' "$f" && codeql=1; done
if [ "$codeql" -eq 1 ]; then ok CodeQL; else warn "no CodeQL workflow"; fi
if grep -qE '^/?(\*)?\.env(\*|\.\*)?$' .gitignore 2>/dev/null; then ok ".env ignored"; else warn ".env not in .gitignore"; fi

echo "== Risky code patterns =="
# check <label> <pattern> [exclude-pattern]: lines matching the exclude pattern are ignored.
check(){
  r=$(grep -rInE "$2" . --include='*.py' --include='*.js' --include='*.mjs' --include='*.cjs' --include='*.ts' --include='*.tsx' --include='*.jsx' \
        --include='*.php' --include='*.java' --include='*.go' --include='*.rb' "${EXCLUDES[@]}" 2>/dev/null \
      | { if [ -n "${3:-}" ]; then grep -vE "$3"; else cat; fi; } | head -5)
  if [ -n "$r" ]; then warn "$1"; echo "$r" | indent; fi
}
check "eval/exec on dynamic input" '(^|[^a-zA-Z_.])(eval|exec)\('
check "shell=True / os.system / child_process.exec" 'shell=True|os\.system\(|child_process.*exec\(|execSync\('
check "unsafe deserialization (pickle / yaml.load / unserialize)" 'pickle\.loads?\(|yaml\.(load|load_all)\(|yaml\.unsafe_load|unserialize\(|ObjectInputStream' 'Loader *= *(yaml\.)?(C?SafeLoader)'
check "weak hash MD5/SHA1" '(md5|sha1)\('
check "SQL string building" 'f["'"'"'][^"'"'"']*(SELECT|INSERT|UPDATE|DELETE)|(SELECT|INSERT|UPDATE|DELETE)[^"'"'"'`]*\$\{|(SELECT|INSERT|UPDATE|DELETE).*["'"'"'] *(\+|%) *[A-Za-z_(]|(SELECT|INSERT|UPDATE|DELETE).*["'"'"']\.format\('
check "TLS verification disabled" 'verify *= *False|rejectUnauthorized: *false|InsecureSkipVerify: *true|NODE_TLS_REJECT_UNAUTHORIZED'
check "innerHTML / dangerouslySetInnerHTML" 'innerHTML *=|dangerouslySetInnerHTML'
check "Math.random for security" 'Math\.random\(\)'

echo "== Docker / CI =="
for df in Dockerfile Containerfile */Dockerfile; do [ -f "$df" ] || continue
  last_user=$(grep -iE '^USER ' "$df" | tail -1 | awk '{print $2}')
  case "$last_user" in
    "") warn "$df runs as root (no USER)";;
    root|0|0:*|root:*) warn "$df: last USER is root";;
    *) ok "$df non-root USER ($last_user)";;
  esac
  grep -iE '^FROM ' "$df" | grep -viE '^FROM +(--platform=[^ ]+ +)?scratch' \
    | grep -qiE ':latest( |$)|^FROM +(--platform=[^ ]+ +)?[^:@ ]+( +AS +[^ ]+)? *$' && warn "$df: unpinned base image (no tag/digest or :latest)"
done
for f in .github/workflows/*.y*ml; do [ -f "$f" ] || continue
  grep -q '^permissions:' "$f" || warn "$f: no top-level permissions block"
  unpinned=$(grep -nE '^[[:space:]]*-?[[:space:]]*uses:[[:space:]]*[^./ ][^@ ]*@' "$f" | grep -vE '@[0-9a-f]{40}( |$)' | grep -v 'docker://' || true)
  if [ -n "$unpinned" ]; then warn "$f: actions not pinned to a full commit SHA"; echo "$unpinned" | head -5 | indent; fi
  grep -q 'pull_request_target' "$f" && warn "$f: uses pull_request_target (review carefully)"
  # Attacker-controlled expressions outside a plain `KEY: ${{ ... }}` line (env:, with:, if:) usually sit in a run: script.
  inj=$(grep -nE '\$\{\{ *github\.(event\.(issue|pull_request|comment|review|review_comment|head_commit|discussion|pages)|head_ref)' "$f" \
        | grep -vE '^[0-9]+:[[:space:]]*-?[[:space:]]*[A-Za-z_][A-Za-z0-9_-]*:[[:space:]]*["'"'"']?\$\{\{' || true)
  if [ -n "$inj" ]; then warn "$f: untrusted github.event/head_ref expression in a script (injection; pass via env:)"; echo "$inj" | head -5 | indent; fi
done

echo "== Dependency scanners (if installed) =="
[ -f package.json ] && command -v npm >/dev/null && npm audit --omit=dev 2>&1 | tail -5
[ -f requirements.txt ] && command -v pip-audit >/dev/null && pip-audit -r requirements.txt 2>&1 | tail -5
command -v osv-scanner >/dev/null && osv-scanner scan source -r . 2>&1 | tail -15
command -v trivy >/dev/null && trivy fs --quiet --severity HIGH,CRITICAL . 2>&1 | tail -15
if command -v gitleaks >/dev/null; then
  # gitleaks >= 8.19 uses `git`/`dir`; `detect` is the deprecated pre-8.19 form. --redact keeps values out of output.
  if gitleaks git --help >/dev/null 2>&1; then
    if git rev-parse --git-dir >/dev/null 2>&1; then gl=(git); else gl=(dir); fi
  else gl=(detect --source); fi
  gitleaks "${gl[@]}" . --no-banner --redact --log-level warn >/dev/null 2>&1 || warn "gitleaks reported leaks or failed (run: gitleaks ${gl[*]} . --redact -v)"
fi

echo; echo "Findings: $issues (heuristic; manual review still required)"
if [ "$STRICT" -eq 1 ] && [ "$issues" -gt 0 ]; then exit 1; fi
exit 0
