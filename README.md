# mcp.duxca.com

Grok / Claude アプリから呼べる **MCP ゲートウェイ**（Rust / Axum）。

参考実装は pascal 上の `~/Github/mcp-test`（Python / Starlette）。
公開は Cloud Run で、`terraform_gcp_app` の Cloud Run domain mapping と `terraform_cf` の Cloudflare DNS record（DNS-only の CNAME）で `https://mcp.duxca.com` に載せる。MCP エンドポイントは組み込みの relay（`/relay/v1`）だけ。

## ローカル起動

**シェルからフォアグラウンドで起動し、Ctrl+C で止める。** 本番（duxca VM）は systemd で動かす（末尾の節）。

```sh
cp .env.example .env
cargo test
cargo run   # Tunnel 無しのゲートウェイ単体（PUBLIC_URL 必須）
```

## アーキテクチャ

```
[Grok / Claude クラウド]
        │ HTTPS
        ▼
 Cloudflare Tunnel  ──►  mcp.duxca.com ゲートウェイ (Axum)
                              │
                              ├─ OAuth 認可サーバ（動的登録 / CIMD / PKCE）※オリジン共通 1 本
                              ├─ GitHub OAuth で本人確認（数値 id allowlist）
                              ├─ 自前 Bearer で POST /relay/v1 を保護
                              ├─ relay（エージェント間メッセージ）
                              └─ SQLite 1 ファイル（DATABASE_PATH）: OAuth と relay の保存先
```

- 許可アカウントは GitHub **数値 id**（login は改名で再利用されうる）。既定: `2429307`（legokichi）。
- OAuth のクライアント・認可の途中・認可コード・トークンは SQLite に置き、再起動しても残る。トークン・認可コード・state・client_secret は SHA-256 だけを保存する。
- MCP は JSON-RPC（`POST /relay/v1`）。OAuth の保護リソースは relay だけ。
- OAuth（`/authorize` `/token` `/register` GitHub コールバック）はホスト共通のまま。GitHub Client Secret は増やさない。

## ルート

| Method | Path | 説明 |
|--------|------|------|
| GET | `/.well-known/oauth-authorization-server` | OAuth AS メタデータ（`none` + CIMD） |
| GET | `/.well-known/oauth-protected-resource` | 保護リソース URL 一覧（relay だけ） |
| GET | `/.well-known/oauth-protected-resource/relay/v1` | 保護リソースメタデータ（RFC 9728） |
| POST | `/register` | 動的クライアント登録（RFC 7591） |
| GET/POST | `/authorize` | 認可（→ GitHub） |
| POST | `/token` | 認可コード / refresh → bearer |
| GET | `/oauth/callback/github` | GitHub OAuth コールバック（river と同じ） |
| GET | `/oauth/setup/github` | GitHub OAuth App 未設定時の案内（503） |

`/` と `/health` は無い（空の 404）。旧パス `/mcp/v3` は廃止（サブドメイン `mcp.` と重複するため）。
stdio の MCP バックエンド（`POST /{service}/{version}`、`/adb/v1` など）は撤去した。いまは 404 を返す。

加えて、組み込みの relay が常に `/relay/v1`（MCP）と `/relay/v1/{health,docs,llms.txt,docs.md}` に生える（次節）。

## relay（エージェント間メッセージ、`/relay/v1`）

[AISupplyGuy/muse-relay](https://github.com/AISupplyGuy/muse-relay) の移植を対称化したもの。Muse も Grok Bot も
同じ MCP エンドポイント `POST /relay/v1` に繋ぎ、名乗った名前どうしでメッセージと添付をやりとりする。`src/relay/` にまとまっている。

- **エンドポイントは 1 本、認証は OAuth のみ。** 静的キーは無い。`/relay/v1` がこのゲートウェイ唯一の OAuth 保護リソース
  - コネクタ登録時の `resource` は `{PUBLIC_URL}/relay/v1`。メタデータは `/.well-known/oauth-protected-resource/relay/v1`
  - `resource` を省略した認可要求も relay に束ねる。relay 以外の `resource` は `invalid_target`
- **部屋 = OAuth の subject（GitHub 数値 id）。** 同じアカウントのトークンなら同じ部屋。部屋をまたいだ参照はできない
- **名乗りは自己申告。** 各ツールで自分を `agent`、相手を `to` で申告する。サーバは資格情報からロールを決めない（部屋の中は本人のエージェントだけなので名前を信頼する）
- **起床 webhook も自己申告。** 受け手が `register_agent` で自分の `webhook_url` / `webhook_secret`（`webhook_url` を登録するなら必須）/ `webhook_auth` を登録し、その名前宛てのメッセージが保存されると POST される
  - 本文 `{"event":"relay.message.created","message":{...}}`、`X-Relay-Signature: sha256=<HMAC-SHA256(webhook_secret, "<timestamp>.<body>")>`、`X-Relay-Timestamp`、`X-Relay-Event`、`webhook_auth` があれば `Authorization`。秘密そのもの（旧 `X-Relay-Secret`）は送らない
  - 受信側は署名だけで認証する（定数時間で比較、タイムスタンプが 5 分より古い配送は捨てる、`message.id` で重複を捨てる）
  - 単発・5 秒タイムアウト・リダイレクトは追わない。同時に送るのは 16 件まで（溢れた分は送らない）
  - `webhook_url` は https で、公開アドレスに限る。localhost・プライベート・リンクローカルなどは登録時に断り、送る直前にも名前を引き直して公開アドレスだけに繋ぐ
  - 登録の値はどのツールの応答にもログにも出ない。登録は DB に残るので、relay の再起動のあとに登録し直す必要は無い
  - `webhook_auth` / `webhook_secret` は送るときに要るので、DB に平文で置く
- ストアは SQLite。スレッド・メッセージ・添付・既読・登録は再起動しても残る
  - メッセージ（と添付）は送ってから 7 日で消え、最後のメッセージが消えたスレッドも消える。登録は消えない
  - 消すのは `send_message` / `register_agent` の書き込みのついで（常駐タスクは無い）
  - メッセージ id（= カーソル）は部屋ごとに数え、部屋を最初に使った時刻の Unix ミリ秒から増える。カウンタも DB に残るので id は戻らない
- 上限（超えると isError。7 日を過ぎたメッセージが消えると空く）
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

## ローカル確認

```sh
curl -s http://127.0.0.1:8000/relay/v1/health
curl -s http://127.0.0.1:8000/.well-known/oauth-authorization-server
# Bearer 無しは 401 + WWW-Authenticate
curl -si -X POST http://127.0.0.1:8000/relay/v1 \
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
| `RELAY_MAX_TOTAL_STORAGE_BYTES` | relay 添付の全部屋の合計上限（既定 67108864 = 64 MB、1 部屋はその半分）。relay の env はこれだけ |
| `DATABASE_PATH` | OAuth と relay を残す SQLite のファイル（既定 `mcp.db`、作業ディレクトリからの相対パス） |
| `SQLITE_WAL_AUTOCHECKPOINT` | 未設定なら SQLite の既定。Litestream と組むときだけ 0 にする |
| `RUST_LOG` | ログの絞り込み（未設定なら `info`） |

## これから

1. ~~GitHub OAuth + bearer~~ ← 済
2. duxca VPC（GCP）へ移設し、Tunnel コネクタをそこへ

## 開発メモ

- webrtc.duxca.com / river.duxca.com と同じく Axum 0.8 + envy + tracing。
- GitHub 側の authorize URL 生成とコード交換は river と同じ `oauth2` クレート（`BasicClient`）。コールバックも river と同じ `/oauth/callback/github`。
- MCP 側の認可サーバ（`/authorize` `/token` `/register` well-known）は自前実装のまま。GitHub の `state` には MCP 側の pending state をそのまま載せる。
- 旧パス `/github/callback` と `/mcp/v3` は廃止。
- CIMD 取得は公開 IP だけに接続する。ローカル DNS が合成アドレスを返すときは Cloudflare DoH にフォールバックする。
- ループバック redirect（`http://localhost/callback`）は RFC 8252 どおりポート違いを許す。
- redirect_uri は `OAUTH_REDIRECT_ALLOWLIST` に載るものだけ受ける。`/register` は `invalid_client_metadata`、CIMD は文書ごと拒否、`/authorize` はリダイレクトせず 400 JSON。fragment・userinfo 付きは常に拒否。
- ローカルは `cargo run`、本番は systemd（次節）。

## duxca VM へのデプロイ

`main` への push で `.github/workflows/deploy.yml` が走り、ビルドしたバイナリと `deploy/` を
`duxca` VM（`duxca.com:4322`）に送って `deploy/install.sh` を sudo 実行する。

- systemd: `mcp-duxca-com.service`（gateway, 127.0.0.1:8000）と
  `mcp-duxca-com-tunnel.service`（cloudflared）。どちらも専用ユーザー `mcp-duxca` で動く。
- 秘密は GitHub Secrets: `MCP_GITHUB_CLIENT_ID`, `MCP_GITHUB_CLIENT_SECRET`, `MCP_TUNNEL_TOKEN`,
  `DUXCA_SSH_KEY`, `DUXCA_KNOWN_HOSTS`。VM 上では `/etc/mcp-duxca-com/`（root:mcp-duxca 640）。
- DB は `/var/lib/mcp-duxca-com/mcp.db`。`install.sh` はゲートウェイを再起動するときだけ、止めてから
  `mcp.db`（と `-wal` / `-shm`）を `/var/lib/mcp-duxca-com/backup/<時刻>/` に写して起動する（新しい 3 世代を残す）。
  スキーマは前進だけで、DB の版がバイナリより新しいと起動しない。バイナリを戻すときは DB もここから戻す。
