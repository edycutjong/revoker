#!/usr/bin/env bash
# Fail if anything in site/ would make a network request at render time.
#
# These pages are served under a strict no-dependency rule: no CDN, no webfonts,
# no analytics, no remote images. That is easy to regress silently — one pasted
# <script src> and the rule is gone — so it is checked rather than trusted.
#
# Deliberately NOT a lookahead regex. `grep -E` has no lookaheads; a pattern
# using one errors out, the shell reads the non-zero exit as "no match", and the
# check passes forever while testing nothing.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

SITE="${1:-site}"
[ -d "$SITE" ] || { echo "no $SITE/ directory"; exit 1; }

# Strip HTML comments before checking. The page carries a commented-out embed
# template for the demo video; a commented tag loads nothing.
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
while IFS= read -r f; do
  rel=${f#"$SITE"/}
  mkdir -p "$WORK/$(dirname "$rel")"
  perl -0777 -pe 's/<!--.*?-->//gs' "$f" > "$WORK/$rel" 2>/dev/null || cp "$f" "$WORK/$rel"
done < <(find "$SITE" -type f \( -name '*.html' -o -name '*.css' -o -name '*.js' \))

fail=0
report() { # pattern, human description
  local hits
  # youtube-nocookie is the one accepted exception: the demo-video embed is a
  # deliberate remote iframe, privacy-mode, and only loads on user interaction
  # with that section. Everything else must be inline.
  hits=$(grep -rInE "$1" "$WORK" 2>/dev/null | grep -v 'youtube-nocookie\.com' || true)
  if [ -n "$hits" ]; then
    echo "::error::$2"
    echo "$hits" | sed "s|$WORK|$SITE|; s/^/    /"
    fail=1
  fi
}

# Resource loads. A remote href on <link rel=canonical|alternate> is metadata,
# not a load, so match only the tags that actually fetch.
report '<script[^>]+src[[:space:]]*=[[:space:]]*"https?:' 'external <script src>'
report '<link[^>]+rel[[:space:]]*=[[:space:]]*"(stylesheet|preload|preconnect|dns-prefetch|prefetch)"[^>]*https?:' 'external <link> resource'
report '<img[^>]+src[[:space:]]*=[[:space:]]*"https?:' 'remote <img src>'
report '<iframe[^>]+src[[:space:]]*=[[:space:]]*"https?:' 'remote <iframe src>'
report '@import[[:space:]]+(url\()?["'\'']?https?:' 'CSS @import from a remote origin'
report '(fonts\.googleapis\.com|fonts\.gstatic\.com|cdn\.jsdelivr|unpkg\.com|cdnjs\.)' 'CDN or webfont host'
report 'googletagmanager|google-analytics|plausible\.io|umami|posthog' 'analytics'

# Runtime fetches. XHR/WebSocket/EventSource to an absolute URL.
report 'fetch\([[:space:]]*["'\'']https?:' 'runtime fetch() to a remote URL'
report 'new[[:space:]]+(WebSocket|EventSource)\([[:space:]]*["'\'']?(wss?|https?):' 'remote socket/EventSource'

if [ "$fail" -ne 0 ]; then
  echo
  echo "$SITE/ is NOT self-contained — see above."
  exit 1
fi
echo "$SITE/ is self-contained (no external resource loads)"
