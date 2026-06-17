#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
GAME_NAME="Snake"
VERSION="1.0.0"
OUTPUT="${PROJECT_ROOT}/bin/${GAME_NAME}_v${VERSION}.tar.gz"

echo "=== Building Snake game ==="
make -C "$SCRIPT_DIR" -f "$SCRIPT_DIR/Makefile" clean
make -C "$SCRIPT_DIR" -f "$SCRIPT_DIR/Makefile" all

echo "=== Packaging ==="
TMPDIR="$(mktemp -d /tmp/snakepack.XXXXXX)"
trap 'rm -rf "$TMPDIR"' EXIT

mkdir -p "$TMPDIR/server/linux"
cp "$PROJECT_ROOT/bin/snake_server.so" "$TMPDIR/server/linux/snakeServer.so"
tar czf "$TMPDIR/server.tar.gz" -C "$TMPDIR/server" linux/

mkdir -p "$TMPDIR/client/linux"
cp "$PROJECT_ROOT/bin/snake_client.so" "$TMPDIR/client/linux/snakeClient.so"
tar czf "$TMPDIR/client.tar.gz" -C "$TMPDIR/client" linux/

cp "$SCRIPT_DIR/metadata.json" "$TMPDIR/metadata.json"

mkdir -p "$(dirname "$OUTPUT")"
tar czf "$OUTPUT" -C "$TMPDIR" metadata.json server.tar.gz client.tar.gz

echo "=== Package created: $OUTPUT ==="
echo "    Contents:"
tar tzf "$OUTPUT"
