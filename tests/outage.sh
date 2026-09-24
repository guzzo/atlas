#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
./bin/passport verify codex-local 1200 >/dev/null
restore() { docker compose start registry >/dev/null; }
trap restore EXIT
docker compose stop registry >/dev/null
docker compose run --rm -T --no-deps toolbox node dist/scripts/outage.js
