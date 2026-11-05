#!/bin/bash
set -euo pipefail

: "${LITESTREAM_BUCKET:?LITESTREAM_BUCKET is required}"
export LITESTREAM_BUCKET

restore_dir="$(mktemp -d ./mcp-db-restore.XXXXXX)"
restore_db="${restore_dir}/mcp.db"

cleanup() {
    rm -rf "$restore_dir"
}
trap cleanup EXIT

restore_flags=()
# 新規環境の初回起動だけ 1 にする。既定ではレプリカが無ければ起動を失敗させ、空 DB での上書きを防ぐ
if [ "${LITESTREAM_ALLOW_EMPTY_RESTORE:-0}" = 1 ]; then
    restore_flags+=(-if-replica-exists)
fi
./litestream restore -config ./litestream.yml "${restore_flags[@]}" -o "$restore_db" ./mcp.db

if [ -f "$restore_db" ]; then
    mv -f "$restore_db" ./mcp.db
fi

cleanup
trap - EXIT

exec ./litestream replicate -config ./litestream.yml -exec ./mcp-duxca-com
