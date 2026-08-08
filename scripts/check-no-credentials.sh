#!/usr/bin/env bash
# An org API key or a raw private key must never reach this repo.
#
# The naive pattern `kh_[A-Za-z0-9_-]{20,}` is wrong: it matches documentation
# slugs like `kh_execute_contract-call`, which is 24 characters after the
# prefix. That fired a false positive and failed CI on a docs file.
#
# Real organisation keys are high-entropy — mixed case AND digits. Doc slugs are
# lowercase words joined by _ and -. Requiring both classes separates them
# without needing a lookahead, which `grep -E` does not have.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

candidates=$(git grep -InE 'kh_[A-Za-z0-9_-]{20,}' -- . 2>/dev/null || true)

# Keep only candidates whose token has an uppercase letter and a digit.
keys=$(echo "$candidates" \
  | grep -E 'kh_[A-Za-z0-9_-]*[A-Z]' 2>/dev/null \
  | grep -E 'kh_[A-Za-z0-9_-]*[0-9]' 2>/dev/null \
  | grep -vE 'your_key|example|placeholder|kh_your' || true)

privkeys=$(git grep -InE 'PRIVATE_KEY[[:space:]]*=[[:space:]]*"?0x[0-9a-fA-F]{64}' -- . 2>/dev/null || true)

if [ -n "$keys" ] || [ -n "$privkeys" ]; then
  echo "::error::credential-shaped string found in tracked files"
  [ -n "$keys" ] && echo "$keys"
  [ -n "$privkeys" ] && echo "$privkeys"
  exit 1
fi
echo "no credentials in tracked files"
