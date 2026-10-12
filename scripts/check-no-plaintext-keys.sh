#!/usr/bin/env bash
# check-no-plaintext-keys.sh
#
# US-03 DoD: Automated log scanner — verifies that no plaintext API key
# (pattern: ask_<8chars>_<48chars>) appears in:
#   1. Any backend server log file passed as arguments
#   2. Any Rust source file under backend/crates/ (static check)
#   3. Any DB migration file under backend/crates/db_migrations/
#
# Usage:
#   ./scripts/check-no-plaintext-keys.sh [logfile...]
#
# Exit codes:
#   0 — no plaintext key found
#   1 — plaintext key pattern found (CI failure)

set -euo pipefail

# Full API key pattern: ask_ + 8 alphanumeric base64url chars + _ + 48 base64url chars
# This matches any real key that would be returned by generate_api_key()
KEY_PATTERN='ask_[A-Za-z0-9_-]{8}_[A-Za-z0-9_-]{48}'

FOUND=0
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

check_file() {
  local file="$1"
  local label="$2"
  if grep -E "$KEY_PATTERN" "$file" >/dev/null 2>&1; then
    echo "❌ FAIL [$label]: Plaintext API key pattern found in: $file"
    grep -En "$KEY_PATTERN" "$file" | head -5
    FOUND=1
  fi
}

# ── 1. Log files passed as CLI arguments ──────────────────────────────────────
for logfile in "$@"; do
  if [[ -f "$logfile" ]]; then
    check_file "$logfile" "server-log"
  else
    echo "⚠️  Log file not found (skipping): $logfile"
  fi
done

# ── 2. Rust source files — keys must never appear in source ───────────────────
# Exclude test fixtures that intentionally contain example-shaped (but fake) keys.
# The pattern check here catches any key with the exact 61-char format.
while IFS= read -r -d '' srcfile; do
  # Skip test files that may contain fake keys of fixed length for testing
  if [[ "$srcfile" == *"tests/"* ]] || [[ "$srcfile" == *"_test.rs" ]]; then
    continue
  fi
  check_file "$srcfile" "rust-src"
done < <(find "$REPO_ROOT/backend/crates" -name '*.rs' -print0)

# ── 3. DB migration SQL files ─────────────────────────────────────────────────
while IFS= read -r -d '' sqlfile; do
  check_file "$sqlfile" "migration-sql"
done < <(find "$REPO_ROOT/backend/crates/db_migrations" -name '*.sql' -print0)

# ── Result ────────────────────────────────────────────────────────────────────
if [[ "$FOUND" -eq 0 ]]; then
  echo "✅ No plaintext API keys found in logs, source, or migrations."
  exit 0
else
  echo ""
  echo "CI FAILURE: Plaintext API key exposure detected. See above for details."
  echo "API keys must never be written to logs, source files, or DB migrations."
  exit 1
fi
