#!/usr/bin/env bash
# Builds the image and checks its runtime contract against the pgmcp-test database.
set -euo pipefail

cd "$(dirname "$0")/.."

IMAGE=postgres-mcp:smoke
NAME=pgmcp-smoke
COMPOSE=(docker compose -f docker-compose.test.yml)
DATABASE_URL='postgres://mcp_ro:test-only-ro@pg19:5432/appdb?sslmode=disable'
API_KEY_VALUE='smoke-test-key-0123456789'
PROTOCOL='2025-11-25'
KEEP=0
STARTED_STACK=0

usage() {
    cat <<'EOF'
Usage: scripts/docker-smoke.sh [--keep] [--help]

Builds postgres-mcp:smoke and checks the running container against the pgmcp-test database.
Starts the pgmcp-test stack only when it is not running, and removes it afterwards.

  --keep   leave a stack started by this run up afterwards
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
            echo "docker-smoke: unknown argument: $arg" >&2
            usage >&2
            exit 2
            ;;
    esac
done

TMP=$(mktemp -d)

cleanup() {
    if docker container inspect "$NAME" >/dev/null 2>&1; then
        docker rm -f "$NAME" >/dev/null
    fi
    rm -rf "$TMP"
    if [ "$STARTED_STACK" -eq 1 ] && [ "$KEEP" -eq 0 ]; then
        "${COMPOSE[@]}" down -v >/dev/null
    fi
}
trap cleanup EXIT

fail() {
    echo "docker-smoke: FAIL: $*" >&2
    exit 1
}

echo "==> docker build -t $IMAGE ."
docker build -t "$IMAGE" .

size_bytes=$(docker image inspect --format '{{.Size}}' "$IMAGE")
size_mib=$((size_bytes / 1048576))
echo "==> image size: ${size_mib} MiB"

image_user=$(docker image inspect --format '{{.Config.User}}' "$IMAGE")
case "$image_user" in
    nonroot:nonroot | 65532) ;;
    *) fail "image user is '$image_user', expected nonroot:nonroot or 65532" ;;
esac

if [ -z "$("${COMPOSE[@]}" ps --status running --quiet)" ]; then
    echo "==> starting pgmcp-test stack"
    STARTED_STACK=1
    "${COMPOSE[@]}" up -d --wait >/dev/null
else
    echo "==> reusing running pgmcp-test stack"
fi

port=""
for candidate in $(seq 18400 18499); do
    if ! (: </dev/tcp/127.0.0.1/"$candidate") 2>/dev/null; then
        port=$candidate
        break
    fi
done
[ -n "$port" ] || fail "no free port in 18400..18499"
BASE="http://127.0.0.1:$port"

if docker container inspect "$NAME" >/dev/null 2>&1; then
    docker rm -f "$NAME" >/dev/null
fi

echo "==> docker run $NAME on $BASE"
docker run -d --name "$NAME" \
    --network pgmcp-test_default \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    -p "127.0.0.1:$port:8432" \
    -e "DATABASE_URL=$DATABASE_URL" \
    -e "API_KEY=$API_KEY_VALUE" \
    --health-interval 2s \
    "$IMAGE" >/dev/null

deadline=$((SECONDS + 60))
while :; do
    running=$(docker inspect --format '{{.State.Running}}' "$NAME")
    [ "$running" = true ] || fail "container exited before becoming healthy"
    health=$(docker inspect --format '{{.State.Health.Status}}' "$NAME")
    if [ "$health" = healthy ]; then
        break
    fi
    if [ "$SECONDS" -ge "$deadline" ]; then
        fail "container not healthy within 60 s (status $health)"
    fi
    sleep 1
done
echo "==> container healthy"

code=$(curl -sS --max-time 10 -o "$TMP/health" -w '%{http_code}' "$BASE/health") \
    || fail "GET /health did not connect"
[ "$code" = 200 ] || fail "GET /health returned $code, expected 200"
[ "$(<"$TMP/health")" = ok ] || fail "GET /health body is not ok"
echo "==> GET /health -> 200 ok"

mcp_post() {
    local body=$1 out=$2
    shift 2
    curl -sS --max-time 10 -o "$out" -w '%{http_code}' -X POST "$BASE/mcp" \
        -H 'Content-Type: application/json' \
        -H 'Accept: application/json, text/event-stream' \
        -H "MCP-Protocol-Version: $PROTOCOL" \
        --data-binary "$body" "$@"
}

LIST='{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
code=$(mcp_post "$LIST" "$TMP/noauth.body" -D "$TMP/noauth.headers") \
    || fail "POST /mcp without key did not connect"
[ "$code" = 401 ] || fail "POST /mcp without key returned $code, expected 401"
grep -qi '^www-authenticate:' "$TMP/noauth.headers" || fail "401 response has no WWW-Authenticate header"
echo "==> POST /mcp without key -> 401 with WWW-Authenticate"

code=$(mcp_post "$LIST" "$TMP/list.body" -H "X-API-Key: $API_KEY_VALUE") \
    || fail "POST /mcp tools/list did not connect"
[ "$code" = 200 ] || fail "tools/list with key returned $code, expected 200"
grep -qF 'execute_query' "$TMP/list.body" || fail "tools/list body does not list execute_query"
echo "==> tools/list with X-API-Key -> 200 lists execute_query"

CALL='{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"execute_query","arguments":{"sql":"SELECT 42 AS answer"}}}'
code=$(mcp_post "$CALL" "$TMP/select.body" -H "X-API-Key: $API_KEY_VALUE") \
    || fail "tools/call SELECT did not connect"
[ "$code" = 200 ] || fail "tools/call SELECT returned $code, expected 200"
grep -qF '"answer":42' "$TMP/select.body" || fail "SELECT 42 result does not contain \"answer\":42"
echo "==> tools/call SELECT 42 -> \"answer\":42"

WRITE='{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"execute_query","arguments":{"sql":"INSERT INTO smoke_probe VALUES (1)"}}}'
code=$(mcp_post "$WRITE" "$TMP/write.body" -H "X-API-Key: $API_KEY_VALUE") \
    || fail "tools/call INSERT did not connect"
[ "$code" = 200 ] || fail "tools/call INSERT returned $code, expected 200"
grep -qF '"isError":true' "$TMP/write.body" || fail "INSERT result is not an error"
grep -qF 'Query rejected' "$TMP/write.body" || fail "INSERT error does not say Query rejected"
echo "==> tools/call INSERT -> isError true, Query rejected"

if docker exec "$NAME" id >/dev/null 2>&1; then
    fail "docker exec $NAME id succeeded; the image should have no shell or coreutils"
fi
echo "==> docker exec id fails (no shell in image)"

readonly_rootfs=$(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$NAME")
[ "$readonly_rootfs" = true ] || fail "ReadonlyRootfs is '$readonly_rootfs', expected true"
echo "==> ReadonlyRootfs true"

echo "docker-smoke: OK image=${size_mib} MiB"
