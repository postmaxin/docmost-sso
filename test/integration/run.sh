#!/usr/bin/env bash
# End-to-end test of docmost-sso against the pinned Docmost image.
# Usage: test/integration/run.sh   (needs Docker with compose v2)
set -euo pipefail
cd "$(dirname "$0")"
compose=(docker compose -f docker-compose.yml)

cleanup() {
  status=$?
  if [ "$status" -ne 0 ]; then
    echo "--- shim logs ---"; "${compose[@]}" logs --no-color sso | tail -n 50 || true
    echo "--- docmost logs ---"; "${compose[@]}" logs --no-color docmost | tail -n 30 || true
  fi
  "${compose[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  exit "$status"
}
trap cleanup EXIT

"${compose[@]}" build --quiet
"${compose[@]}" up -d --quiet-pull postgres redis docmost mock-oidc sso docs
"${compose[@]}" run --rm --no-deps tester
echo "--- shim sign-in log lines ---"
"${compose[@]}" logs --no-color --no-log-prefix sso | grep '"event":"signin"' || true
