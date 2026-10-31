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

加えて、組み込みの relay が常に `/relay/v1`（MCP）と `/relay/v1/{health,docs,llms.txt,docs.md}` に生える（次節）。

## relay（エージェント間メッセージ、`/relay/v1`）

[AISupplyGuy/muse-relay](https://github.com/AISupplyGuy/muse-relay) の移植を対称化したもの。Muse も Grok Bot も
同じ MCP エンドポイント `POST /relay/v1` に繋ぎ、名乗った名前どうしでメッセージと添付をやりとりする。`src/relay/` にまとまっている。

- **エンドポイントは 1 本、認証は OAuth のみ。** 静的キーは無い。`/relay/v1` は `MCP_SERVICES` とは別に OAuth の保護リソースとして組み込みで登録される
  - コネクタ登録時の `resource` は `{PUBLIC_URL}/relay/v1`。メタデータは `/.well-known/oauth-protected-resource/relay/v1`
  - 他サービス向けのトークンは relay で 401、relay 向けのトークンは他サービスで 401（`WWW-Authenticate` の形は既存 MCP と同じ）
  - `resource` 省略時の既定は従来どおり「stdio サービスが 1 本ならそれ」。relay は数に入れないので、relay へ繋ぐクライアントは `resource` を送る必要がある
  - `MCP_SERVICES` でサービス名 `relay` は使えない（予約）
- **部屋 = OAuth の subject（GitHub 数値 id）。** 同じアカウントのトークンなら同じ部屋。部屋をまたいだ参照はできない
- **名乗りは自己申告。** 各ツールで自分を `agent`、相手を `to` で申告する。サーバは資格情報からロールを決めない（部屋の中は本人のエージェントだけなので名前を信頼する）
- **起床 webhook も自己申告。** 受け手が `register_agent` で自分の `webhook_url` / `webhook_secret`（`webhook_url` を登録するなら必須）/ `webhook_auth` を登録し、その名前宛てのメッセージが保存されると POST される
  - 本文 `{"event":"relay.message.created","message":{...}}`、`X-Relay-Signature: sha256=<HMAC-SHA256(webhook_secret, "<timestamp>.<body>")>`、`X-Relay-Timestamp`、`X-Relay-Event`、`webhook_auth` があれば `Authorization`。秘密そのもの（旧 `X-Relay-Secret`）は送らない
  - 受信側は署名だけで認証する（定数時間で比較、タイムスタンプが 5 分より古い配送は捨てる、`message.id` で重複を捨てる）
  - 単発・5 秒タイムアウト・リダイレクトは追わない。同時に送るのは 16 件まで（溢れた分は送らない）
  - `webhook_url` は https で、公開アドレスに限る。localhost・プライベート・リンクローカルなどは登録時に断り、送る直前にも名前を引き直して公開アドレスだけに繋ぐ
  - 登録の値はどのツールの応答にもログにも出ない。登録はメモリだけなので、エージェントは起動のたびに登録し直す
- ストアはメモリだけ。再起動でスレッド・メッセージ・添付・登録は消える
  - メッセージ id（= カーソル）は部屋ごとに数え、部屋を最初に使った時刻の Unix ミリ秒から増えるので、再起動前のカーソルもそのまま使える
- 上限（超えると isError。自動では消さない）
  - 添付は 1 メッセージ 5 件・合計 3 MB まで。リクエストボディは 6 MB まで。1 スレッド 500 件まで
  - 部屋ごと: 10000 件、本文などのデータ 32 MB（概算）、添付 32 MB、登録 100 件。全体: 20000 件、データ 64 MB、添付 `RELAY_MAX_TOTAL_STORAGE_BYTES`（既定 64 MB。部屋ごとの添付はその半分）
  - 同時に待機できる `ask` / `check_messages` は部屋ごと 16 件、全体 64 件。バッチは 32 件まで、応答は合計 16 MB まで
- 待機は `ask` が最大 240 秒（既定 55 秒）、`check_messages` が最大 55 秒。Ctrl+C では待機中のものも即座に返して止まる

ツール: `send_message` / `ask` / `check_messages` / `get_thread` / `list_threads` / `mark_read` / `get_attachment` /
`list_agents` / `register_agent` / `unregister_agent`。引数と返り値は `GET /relay/v1/docs` が正。

| Method | Path | 認証 | 説明 |
|--------|------|------|------|
| POST | `/relay/v1` | OAuth Bearer（resource = relay） | MCP JSON-RPC（stateless streamable HTTP、バッチ可）。GET は 405、DELETE は 200 |
| GET | `/relay/v1/health` | なし | `{"status":"ok"}` |
| GET | `/relay/v1/docs`（`/llms.txt`, `/docs.md`） | なし | エージェント向けの使い方（テキスト） |

### 会話ログ

relay の処理は tracing の info で会話ログを出す。本番は systemd 常駐なので journald に入る。

- メッセージ保存（部屋・id・スレッド・from・to・本文全文・添付のファイル名/MIME/サイズ）、ask の結果、check_messages の配達件数、
  mark_read、register/unregister（webhook の有無だけ）、webhook の結果と所要 ms、get_attachment
- 添付の中身（base64）と webhook の URL・auth・secret は出さない。名前と本文は改行をエスケープして 1 行に収める

```sh
journalctl -u mcp-duxca-com -f                       # 全部
journalctl -u mcp-duxca-com -f | grep 'relay:'       # relay だけ
journalctl -u mcp-duxca-com -f | grep 'relay: message stored'
```

`RUST_LOG` が未設定なら `info` が既定。relay だけ見たいときは `RUST_LOG=warn,mcp_duxca_com::relay=info`
（`mcp_duxca_com::relay` 配下が relay のターゲット）。

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
| `BIND_ADDR` | 待受アドレス（既定 `127.0.0.1`。公開は Tunnel 経由なので外向きには開けない） |
| `PORT` | 待受ポート（既定 8000） |
| `OAUTH_REDIRECT_ALLOWLIST` | カンマ区切りの redirect_uri 許可リスト。末尾 `/*` は 1 セグメントだけ、末尾 `/` は配下すべて、それ以外はパス完全一致。ポート無しのループバックはポートを問わない。未設定時は `src/auth.rs` の `DEFAULT_REDIRECT_ALLOWLIST`（ChatGPT / Claude / Grok / ループバック） |
| `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET` | GitHub OAuth App |
| `ALLOWED_GITHUB_IDS` | カンマ区切り数値 id |
| `MCP_SERVICES` | カンマ区切り `name/version`（空なら `default/v1`） |
| `MCP_<NAME>_<VER>_COMMAND` | サービスごとの起動コマンド |
| `MCP_<NAME>_<VER>_CWD` | サービスごとの cwd（省略時は下記） |
| `CLAUDE_MCP_COMMAND` | `MCP_SERVICES` 未設定時のフォールバック（既定 `claude mcp serve`） |
| `CLAUDE_CWD` | 上記フォールバック / 個別 CWD 未設定時の cwd（省略時 `$HOME`） |
| `RELAY_MAX_TOTAL_STORAGE_BYTES` | relay 添付の全部屋の合計上限（既定 67108864 = 64 MB、1 部屋はその半分）。relay の env はこれだけ |
| `RUST_LOG` | ログの絞り込み（未設定なら `info`） |
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
- redirect_uri は `OAUTH_REDIRECT_ALLOWLIST` に載るものだけ受ける。`/register` は `invalid_client_metadata`、CIMD は文書ごと拒否、`/authorize` はリダイレクトせず 400 JSON。fragment・userinfo 付きは常に拒否。
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
