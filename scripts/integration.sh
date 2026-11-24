#!/usr/bin/env bash
# Runs every cargo test target against the pgmcp-test PostgreSQL stack.
set -euo pipefail

cd "$(dirname "$0")/.."

COMPOSE=(docker compose -f docker-compose.test.yml)
KEEP=0

usage() {
    cat <<'EOF'
Usage: scripts/integration.sh [--keep] [--help]

Starts the pgmcp-test stack, runs all cargo test targets, then removes the stack (down -v).

  --keep   reuse a running stack and leave it up afterwards
  --help   show this help
EOF
}

for arg in "$@"; do
    case "$arg" in
        --keep) KEEP=1 ;;
        --help | -h)
            usage
            exit 0
            ;;
        *)
            echo "integration: unknown argument: $arg" >&2
            usage >&2
            exit 2
            ;;
    esac
done

LOG=$(mktemp)

cleanup() {
    rm -f "$LOG"
    if [ "$KEEP" -eq 0 ]; then
        "${COMPOSE[@]}" down -v >/dev/null
    fi
}
trap cleanup EXIT

if [ "$KEEP" -eq 0 ] && [ -n "$("${COMPOSE[@]}" ps --status running --quiet)" ]; then
    echo "==> stack already running: removing it for a fresh start"
    "${COMPOSE[@]}" down -v
fi

echo "==> docker compose up --wait"
"${COMPOSE[@]}" up -d --wait

echo "==> cargo test --locked -- --test-threads=4"
status=0
cargo test --locked -- --test-threads=4 >"$LOG" 2>&1 || status=$?

if [ "$status" -ne 0 ]; then
    cat "$LOG"
    echo "integration: FAILED exit=$status" >&2
    exit "$status"
fi

awk '
    /^ +Running / { name = ($2 == "unittests") ? $3 : $2 }
    /^ +Doc-tests / { name = "doc-tests " $2 }
    /^test result:/ { print name ": " $0 }
' "$LOG"

passed=$(awk '/^test result:/ { for (i = 1; i <= NF; i++) if ($i == "passed;") total += $(i - 1) } END { print total + 0 }' "$LOG")
echo "integration: OK passed=$passed"
