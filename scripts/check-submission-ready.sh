#!/usr/bin/env bash
# Fails if anything judge-facing still carries a placeholder.
#
# The README links a demo video and a BUIDL page that do not exist until the
# human uploads and submits. A badge pointing at the literal string
# FILL_YOUTUBE_URL is worse than no badge, and it is exactly the kind of thing
# that survives to submission day because everyone assumes someone else caught
# it. So CI catches it instead.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

fail=0
note() { printf '  %s\n' "$1"; }

echo "submission readiness"
echo

# --- placeholders -----------------------------------------------------------
# `0x...` inside an env-var example is a documentation convention, not an
# unfilled field, so it is deliberately not in this pattern.
hits=$(grep -rInE 'FILL_[A-Z_]+|⟨FILL⟩|VIDEO_ID|youtu\.be/xxx' \
         --include='*.md' --include='*.html' --include='*.json' . 2>/dev/null \
       | grep -vE 'node_modules|\.env\.example|check-submission-ready' || true)
if [ -n "$hits" ]; then
  note "✗ unfilled placeholders:"
  echo "$hits" | sed 's/^/      /'
  fail=1
else
  note "✓ no placeholders"
fi

# --- the three mandatory submission artifacts -------------------------------
grep -q 'sepolia.etherscan.io/tx/0x' README.md \
  && note "✓ real transaction linked" \
  || { note "✗ README links no transaction"; fail=1; }

grep -qE 'youtube\.com|youtu\.be' README.md \
  && note "✓ demo video linked" \
  || { note "✗ README links no demo video"; fail=1; }

[ -f LICENSE ] && note "✓ LICENSE present" || { note "✗ LICENSE missing"; fail=1; }

# --- the Pages site --------------------------------------------------------
[ -f site/index.html ] && note "✓ site/index.html present" || { note "✗ site/index.html missing"; fail=1; }
[ -f site/CNAME ] && note "✓ site/CNAME → $(cat site/CNAME 2>/dev/null)" || { note "✗ site/CNAME missing"; fail=1; }
[ -f site/assets/og-image.png ] && note "✓ og:image asset present" || { note "✗ og:image asset missing"; fail=1; }
[ -f site/pitch.html ] && note "✓ site/pitch.html present" || { note "✗ site/pitch.html missing"; fail=1; }

# --- images the README renders must actually be tracked ---------------------
missing=0
while read -r img; do
  [ -z "$img" ] && continue
  git ls-files --error-unmatch "$img" >/dev/null 2>&1 || { note "✗ untracked image: $img"; missing=1; }
done < <(grep -oE 'src="(docs|assets)/[^"]+"' README.md | sed 's/src="//;s/"//')
[ "$missing" -eq 0 ] && note "✓ README images tracked" || fail=1

# --- credentials must never be committed ------------------------------------
# Delegated to check-no-credentials.sh, which CI already runs, rather than
# re-implemented here. This script used to carry its own weaker copy of the
# pattern and reported a permanent false positive on the documentation slug
# `kh_execute_contract-call` — 24 characters after the prefix, so it matched
# `kh_[A-Za-z0-9_-]{20,}`. One definition, one behaviour, no drift.
if bash "$(dirname "$0")/check-no-credentials.sh" >/dev/null 2>&1; then
  note "✓ no credentials committed"
else
  note "✗ credential-shaped string in tracked files"
  bash "$(dirname "$0")/check-no-credentials.sh" 2>&1 | sed 's/^/      /'
  fail=1
fi

echo
if [ "$fail" -ne 0 ]; then
  echo "NOT READY — fix the ✗ items above."
  exit 1
fi
echo "READY."
