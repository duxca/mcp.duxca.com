# mcp.duxca.com

Grok / Claude アプリから呼べる **MCP ゲートウェイ**（Rust / Axum）。

参考実装は pascal 上の `~/Github/mcp-test`（Python / Starlette）。
公開は Cloudflare Tunnel で `https://mcp.duxca.com` に載せる。バックエンドは `McpBackend` で差し替え可能。

## 起動モード（唯一のサポート）

**シェルからフォアグラウンドで起動し、Ctrl+C で全部止める。** Daemon / systemd / nohup はサポートしない。

- オフ単位はゲートウェイ全体（サービス単位の常駐オンオフはしない）
- Cloudflare Tunnel も同じセッションで起動する
- 止める = CLI を終了する（MCP 子プロセスも `kill_on_drop` で一緒に落ちる）

```sh
cp .env.example .env   # または .secrets/runtime.env を用意
./scripts/run.sh
# Ctrl+C → gateway + tunnel + MCP children を停止
```

オプション:

| 変数 / 使い方 | 意味 |
|---------------|------|
| `MCP_BIN=./target/debug/mcp-duxca-com` | ビルド済みバイナリを直接起動（未設定時は `cargo run`） |
| `MCP_USE_RELEASE=1` | `target/release/mcp-duxca-com` があればそれを使う |
| `CLOUDFLARED_TOKEN` / `TUNNEL_TOKEN` | Tunnel トークン（環境変数。値はログに出さない） |
| `CLOUDFLARED_TOKEN_FILE` | トークンファイルパス。未設定時の探索順: `/home/box/.cloudflared/mcp-duxca-com.token` → `.secrets/tunnel.token` |

トークンが無い／`cloudflared` が無い場合は **ゲートウェイのみ** で起動し（ローカル確認・テスト向け）、警告を出す。

```sh
cargo test
cargo run   # Tunnel 無しのゲートウェイ単体でも可（PUBLIC_URL 必須）
```

## アーキテクチャ

```
[Grok / Claude クラウド]
        │ HTTPS
        ▼
 Cloudflare Tunnel  ──►  mcp.duxca.com ゲートウェイ (Axum)   ← 同じシェル／Ctrl+C で両方停止
                              │
                              ├─ OAuth 認可サーバ（動的登録 / CIMD / PKCE）※オリジン共通 1 本
                              ├─ GitHub OAuth で本人確認（数値 id allowlist）
                              ├─ 自前 Bearer で POST /{service}/{version} を保護
                              └─ 設定駆動の複数 McpBackend
                                    ├─ StdioMcpBackend（サービスごと・親終了で kill_on_drop）
                                    └─ （将来）HTTP MCP など差し替え
```

- 許可アカウントは GitHub **数値 id**（login は改名で再利用されうる）。既定: `2429307`（legokichi）。
- トークンはメモリだけ。再起動で消える（mcp-test と同じ）。
- MCP は JSON-RPC（`POST /{service}/{version}`）。サービス名・バージョンは環境変数で追加・差し替え。
- OAuth（`/authorize` `/token` `/register` GitHub コールバック）はホスト共通のまま。GitHub Client Secret は増やさない。

## ルート

| Method | Path | 説明 |
|--------|------|------|
| GET | `/` | 登録済み MCP パス一覧 |
| GET | `/health` | 生存確認（`services` 含む） |
| GET | `/.well-known/oauth-authorization-server` | OAuth AS メタデータ（`none` + CIMD） |
| GET | `/.well-known/oauth-protected-resource` | 全リソース URL 一覧 |
| GET | `/.well-known/oauth-protected-resource/{service}/{version}` | 保護リソースメタデータ（RFC 9728） |
| POST | `/register` | 動的クライアント登録（RFC 7591） |
| GET/POST | `/authorize` | 認可（→ GitHub） |
| POST | `/token` | 認可コード / refresh → bearer |
| GET | `/oauth/callback/github` | GitHub OAuth コールバック（river と同じ） |
| GET | `/oauth/setup/github` | GitHub OAuth App 未設定時の案内（503） |
| POST | `/{service}/{version}` | MCP JSON-RPC（有効な Bearer 必須） |

旧パス `/mcp/v3` は廃止（サブドメイン `mcp.` と重複するため）。

## GitHub OAuth App の設定

1. **新規は作らない**。pascal の `~/Github/mcp-test` が使っている GitHub OAuth App を流用する
2. その App の **Authorization callback URL** に `https://mcp.duxca.com/oauth/callback/github` を追加（または差し替え）
3. Client ID / Client Secret は mcp-test 側の env（mise 等）からコピーして環境変数へ（リポやチャットに書かない）

```sh
PUBLIC_URL=https://mcp.duxca.com
GITHUB_CLIENT_ID=...
GITHUB_CLIENT_SECRET=...
ALLOWED_GITHUB_IDS=2429307
PORT=8000
```

ローカルだけなら `PUBLIC_URL=http://127.0.0.1:8000` で可（HTTPS 以外は localhost のみ）。

## 複数 MCP サービス

```sh
# 例: /codex-sub/v1, /claude-sub/v1, /adb/v1（いずれも設定駆動）
# 起動コマンドは pascal に各 MCP を入れたあとで指定する（パスはここで決めない）
MCP_SERVICES=codex-sub/v1,claude-sub/v1,adb/v1
MCP_CODEX_SUB_V1_COMMAND=
MCP_CLAUDE_SUB_V1_COMMAND=
MCP_ADB_V1_COMMAND=
```

- `MCP_SERVICES` … カンマ区切りの `name/version`
- 各サービスに `MCP_<NAME>_<VERSION>_COMMAND`（必須）と任意の `_CWD`
- 名前・バージョンの非英数字は `_` に置換して大文字化（`my-notes/v1` → `MCP_MY_NOTES_V1_COMMAND`）
- サービス名: `[a-z0-9]` またはハイフン付き。バージョン: `v` + 数字（`v1`, `v2`, `v10` …）
- `MCP_SERVICES` が空のときは `default/v1` を 1 本立て、`CLAUDE_MCP_COMMAND` / `CLAUDE_CWD` を使う
- 認可時の `resource`（RFC 8707）はサービスが複数なら必須。1 本だけのときは省略可
- サービスをオフにするには **CLI（`./scripts/run.sh`）を止める**。常駐プロセスは持たない。

## ローカル確認

```sh
curl -s http://127.0.0.1:8000/health
curl -s http://127.0.0.1:8000/.well-known/oauth-authorization-server
# Bearer 無しは 401 + WWW-Authenticate
curl -si -X POST http://127.0.0.1:8000/default/v1 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

環境変数:

| 変数 | 意味 |
|------|------|
| `PUBLIC_URL` | 公開オリジン（スキーム+ホスト） |
| `PORT` | 待受（既定 8000） |
| `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET` | GitHub OAuth App |
| `ALLOWED_GITHUB_IDS` | カンマ区切り数値 id |
| `MCP_SERVICES` | カンマ区切り `name/version`（空なら `default/v1`） |
| `MCP_<NAME>_<VER>_COMMAND` | サービスごとの起動コマンド |
| `MCP_<NAME>_<VER>_CWD` | サービスごとの cwd（省略時は下記） |
| `CLAUDE_MCP_COMMAND` | `MCP_SERVICES` 未設定時のフォールバック（既定 `claude mcp serve`） |
| `CLAUDE_CWD` | 上記フォールバック / 個別 CWD 未設定時の cwd（省略時 `$HOME`） |
| `CLOUDFLARED_TOKEN_FILE` | Tunnel トークンファイル（`scripts/run.sh`） |
| `MCP_BIN` | ゲートウェイ実行ファイル（`scripts/run.sh`） |

## これから

1. ~~GitHub OAuth + bearer~~ ← 済
2. ~~パスベース複数 MCP~~ ← 済（stdio ブリッジは骨格のまま）
3. `StdioMcpBackend` の本格 stdio JSON-RPC ブリッジ
4. duxca VPC（GCP）へ移設し、Tunnel コネクタをそこへ

## 開発メモ

- webrtc.duxca.com / river.duxca.com と同じく Axum 0.8 + envy + tracing。
- GitHub 側の authorize URL 生成とコード交換は river と同じ `oauth2` クレート（`BasicClient`）。コールバックも river と同じ `/oauth/callback/github`。
- MCP 側の認可サーバ（`/authorize` `/token` `/register` well-known）は自前実装のまま。GitHub の `state` には MCP 側の pending state をそのまま載せる。
- 旧パス `/github/callback` と `/mcp/v3` は廃止。
- CIMD 取得は公開 IP だけに接続する。ローカル DNS が合成アドレスを返すときは Cloudflare DoH にフォールバックする。
- ループバック redirect（`http://localhost/callback`）は RFC 8252 どおりポート違いを許す。
- 起動は `./scripts/run.sh` のみサポート。常時起動前提の運用はしない。

## duxca VM へのデプロイ（adb/v1 のみ）

`main` への push で `.github/workflows/deploy.yml` が走り、ビルドしたバイナリと `deploy/` を
`duxca` VM（`duxca.com:4322`）に送って `deploy/install.sh` を sudo 実行する。

- systemd: `mcp-duxca-com.service`（gateway, 127.0.0.1:8000, `MCP_SERVICES=adb/v1`, `ADB_MCP_ALLOW_SHELL=1`）と
  `mcp-duxca-com-tunnel.service`（cloudflared）。どちらも専用ユーザー `mcp-duxca` で動く。
- adbmcp は FlashZ/adb-mcp をコミット固定で `/opt/mcp-duxca-com/adbmcp` の venv に入れる。
- 秘密は GitHub Secrets: `MCP_GITHUB_CLIENT_ID`, `MCP_GITHUB_CLIENT_SECRET`, `MCP_TUNNEL_TOKEN`,
  `DUXCA_SSH_KEY`, `DUXCA_KNOWN_HOSTS`。VM 上では `/etc/mcp-duxca-com/`（root:mcp-duxca 640）。
- 端末は Termux から `ssh -p 4322 -R 5555:127.0.0.1:5555 legokichi@duxca.com` で転送し、
  MCP の `connect` ツールで `127.0.0.1:5555` に繋ぐ。
