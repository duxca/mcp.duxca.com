#!/usr/bin/env bash
# duxca VM 上で sudo 実行する。CI から呼ばれる想定。
#   sudo ./install.sh <staging-dir>
# staging-dir には mcp-duxca-com（バイナリ）, *.service と、
# 任意で runtime.env / tunnel.token（秘密。あれば置き換える）がある。
set -euo pipefail
SRC="${1:?staging dir}"
ADBMCP_REF=84533098932fb0a7c866e3f3b30a6da8d9311f90   # FlashZ/adb-mcp

export DEBIAN_FRONTEND=noninteractive
need=()
command -v adb >/dev/null || need+=(adb)
dpkg -s python3-venv >/dev/null 2>&1 || need+=(python3-venv)
if ((${#need[@]})); then apt-get update -q && apt-get install -yq "${need[@]}"; fi

id mcp-duxca >/dev/null 2>&1 || useradd --system --home-dir /var/lib/mcp-duxca-com --shell /usr/sbin/nologin mcp-duxca
install -d -o mcp-duxca -g mcp-duxca -m 750 /var/lib/mcp-duxca-com
install -d -m 755 /opt/mcp-duxca-com/bin
install -d -o root -g mcp-duxca -m 750 /etc/mcp-duxca-com

# adbmcp（コミット固定）
stamp=/opt/mcp-duxca-com/adbmcp/.ref
if [[ "$(cat "$stamp" 2>/dev/null)" != "$ADBMCP_REF" ]]; then
  rm -rf /opt/mcp-duxca-com/adbmcp
  python3 -m venv /opt/mcp-duxca-com/adbmcp
  /opt/mcp-duxca-com/adbmcp/bin/pip install -q --upgrade pip
  /opt/mcp-duxca-com/adbmcp/bin/pip install -q "https://github.com/FlashZ/adb-mcp/archive/${ADBMCP_REF}.tar.gz"
  echo "$ADBMCP_REF" > "$stamp"
fi

install -m 755 "$SRC/mcp-duxca-com" /opt/mcp-duxca-com/bin/mcp-duxca-com
for f in runtime.env tunnel.token; do
  if [[ -s "$SRC/$f" ]]; then install -o root -g mcp-duxca -m 640 "$SRC/$f" "/etc/mcp-duxca-com/$f"; fi
  [[ -f "/etc/mcp-duxca-com/$f" ]] || { echo "missing /etc/mcp-duxca-com/$f" >&2; exit 1; }
done
install -m 644 "$SRC/mcp-duxca-com.service" "$SRC/mcp-duxca-com-tunnel.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable -q mcp-duxca-com.service mcp-duxca-com-tunnel.service
systemctl restart mcp-duxca-com.service
systemctl restart mcp-duxca-com-tunnel.service
sleep 3
systemctl is-active mcp-duxca-com.service mcp-duxca-com-tunnel.service
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:8000/adb/v1)
echo "local POST /adb/v1 -> $code"
[[ "$code" == 401 ]]
