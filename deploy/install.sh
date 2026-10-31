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

# 変わったものだけ再起動する。
# トンネルは ssh.duxca.com（= CI の SSH 自身の輸送路）も運ぶので、無駄に再起動すると CI が切断される。
restart_gw=0 restart_tun=0

# adbmcp（コミット固定）。ゲートウェイの子プロセスとして動くので、作り直したらゲートウェイごと再起動して入れ替える。
stamp=/opt/mcp-duxca-com/adbmcp/.ref
if [[ "$(cat "$stamp" 2>/dev/null)" != "$ADBMCP_REF" ]]; then
  rm -rf /opt/mcp-duxca-com/adbmcp
  python3 -m venv /opt/mcp-duxca-com/adbmcp
  /opt/mcp-duxca-com/adbmcp/bin/pip install -q --upgrade pip
  /opt/mcp-duxca-com/adbmcp/bin/pip install -q "https://github.com/FlashZ/adb-mcp/archive/${ADBMCP_REF}.tar.gz"
  echo "$ADBMCP_REF" > "$stamp"
  restart_gw=1
fi

# 上書き前に変更を検出する。宛先が無ければ cmp は失敗する = 変更ありとして扱う。
changed() { ! cmp -s "$1" "$2"; }
changed "$SRC/mcp-duxca-com" /opt/mcp-duxca-com/bin/mcp-duxca-com && restart_gw=1
changed "$SRC/mcp-duxca-com.service" /etc/systemd/system/mcp-duxca-com.service && restart_gw=1
changed "$SRC/mcp-duxca-com-tunnel.service" /etc/systemd/system/mcp-duxca-com-tunnel.service && restart_tun=1
[[ -s "$SRC/runtime.env" ]] && changed "$SRC/runtime.env" /etc/mcp-duxca-com/runtime.env && restart_gw=1
[[ -s "$SRC/tunnel.token" ]] && changed "$SRC/tunnel.token" /etc/mcp-duxca-com/tunnel.token && restart_tun=1

install -m 755 "$SRC/mcp-duxca-com" /opt/mcp-duxca-com/bin/mcp-duxca-com
for f in runtime.env tunnel.token; do
  if [[ -s "$SRC/$f" ]]; then install -o root -g mcp-duxca -m 640 "$SRC/$f" "/etc/mcp-duxca-com/$f"; fi
  [[ -f "/etc/mcp-duxca-com/$f" ]] || { echo "missing /etc/mcp-duxca-com/$f" >&2; exit 1; }
done
install -m 644 "$SRC/mcp-duxca-com.service" "$SRC/mcp-duxca-com-tunnel.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable -q mcp-duxca-com.service mcp-duxca-com-tunnel.service

if ((restart_gw)); then
  systemctl restart mcp-duxca-com.service
elif systemctl is-active -q mcp-duxca-com.service; then
  echo "mcp-duxca-com.service: 変更なし。再起動をスキップ"
else
  systemctl start mcp-duxca-com.service
fi

if ! systemctl is-active -q mcp-duxca-com-tunnel.service; then
  # 動いていないトンネルはこの SSH を運んでいないので、その場で起動してよい（新しい設定で上がる）。
  systemctl start mcp-duxca-com-tunnel.service
elif ((restart_tun)); then
  # インラインで restart すると、cloudflared の graceful shutdown がこの SSH ストリームの終了を待ち、
  # 約30秒後に SSH ごと切れる。install が返って SSH が閉じた後に再起動されるよう遅延予約する。
  systemd-run --on-active=10s --collect /usr/bin/systemctl restart mcp-duxca-com-tunnel.service
  echo "mcp-duxca-com-tunnel.service: 変更あり。10秒後の再起動を予約"
else
  echo "mcp-duxca-com-tunnel.service: 変更なし。再起動をスキップ"
fi

sleep 3
# 以下のローカル確認はトンネルを経由しないので、遅延再起動の影響を受けない。
systemctl is-active mcp-duxca-com.service mcp-duxca-com-tunnel.service
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:8000/adb/v1)
echo "local POST /adb/v1 -> $code"
[[ "$code" == 401 ]]
