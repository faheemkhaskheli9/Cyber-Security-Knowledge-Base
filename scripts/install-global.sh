#!/usr/bin/env bash
# Make your knowledge-base repos available to every Claude Code session.
# Clones them under ~/kb and imports each one from the user-level ~/.claude/CLAUDE.md.
# Safe to re-run. Repos that fail to clone (e.g. private repo without auth) are skipped.
set -u
OWNER="faheemkhaskheli9"
REPOS=(Cyber-Security-Knowledge-Base AI-Knowledge-Base Personal-Knowledge-Base)
mkdir -p "$HOME/kb" "$HOME/.claude/skills"
CFG="$HOME/.claude/CLAUDE.md"; touch "$CFG"
for r in "${REPOS[@]}"; do
  d="$HOME/kb/$r"
  if [ -d "$d/.git" ]; then git -C "$d" pull -q --ff-only || echo "[!] pull failed: $r"
  else git clone -q --depth 1 "https://github.com/$OWNER/$r" "$d" || { echo "[!] skipped $r (clone failed)"; continue; }; fi
  [ -f "$d/CLAUDE.md" ] && ! grep -qF "@$d/CLAUDE.md" "$CFG" && printf '@%s/CLAUDE.md\n' "$d" >> "$CFG"
  [ -d "$d/.claude/skills" ] && cp -rn "$d/.claude/skills/." "$HOME/.claude/skills/"
done
echo "Done. Imports in $CFG:"; cat "$CFG"
