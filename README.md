# mcp.duxca.com

Grok / Claude アプリから呼べる **MCP ゲートウェイ**（Rust / Axum）。

参考実装は pascal 上の `~/Github/mcp-test`（Python / Starlette）。
公開は Cloudflare Tunnel で `https://mcp.duxca.com` に載せる。バックエンドは `McpBackend` で差し替え可能。

## アーキテクチャ

```
[Grok / Claude クラウド]
        │ HTTPS
        ▼
 Cloudflare Tunnel  ──►  mcp.duxca.com ゲートウェイ (Axum)
                              │
                              ├─ OAuth 認可サーバ（動的登録 / CIMD / PKCE）
                              ├─ GitHub OAuth で本人確認（数値 id allowlist）
                              ├─ 自前 Bearer で POST /mcp/v3 を保護
                              └─ McpBackend
                                    ├─ StdioMcpBackend（claude mcp serve）← 骨格
                                    └─ （将来）HTTP MCP など差し替え
```

- 許可アカウントは GitHub **数値 id**（login は改名で再利用されうる）。既定: `2429307`（legokichi）。
- トークンはメモリだけ。再起動で消える（mcp-test と同じ）。
- MCP は JSON-RPC 1 本（`POST /mcp/v3`）。

## ルート

| Method | Path | 説明 |
|--------|------|------|
| GET | `/` | 案内 |
| GET | `/health` | 生存確認 |
| GET | `/.well-known/oauth-authorization-server` | OAuth AS メタデータ（`none` + CIMD） |
| GET | `/.well-known/oauth-protected-resource/mcp/v3` | 保護リソースメタデータ（RFC 9728） |
| POST | `/register` | 動的クライアント登録（RFC 7591） |
| GET/POST | `/authorize` | 認可（→ GitHub） |
| POST | `/token` | 認可コード / refresh → bearer |
| GET | `/github/callback` | GitHub OAuth コールバック |
| GET | `/github/setup` | GitHub App 未設定時の案内（503） |
| POST | `/mcp/v3` | MCP JSON-RPC（有効な Bearer 必須） |

## GitHub OAuth App の設定

1. [GitHub → Settings → Developer settings → OAuth Apps](https://github.com/settings/developers) で新規作成
2. **Authorization callback URL**: `https://mcp.duxca.com/github/callback`
3. Client ID / Client Secret を環境変数へ（リポやチャットに書かない）

```sh
PUBLIC_URL=https://mcp.duxca.com
GITHUB_CLIENT_ID=...
GITHUB_CLIENT_SECRET=...
ALLOWED_GITHUB_IDS=2429307
PORT=8000
```

ローカルだけなら `PUBLIC_URL=http://127.0.0.1:8000` で可（HTTPS 以外は localhost のみ）。

## ローカル起動

```sh
cp .env.example .env
cargo run
cargo test
```

確認:

```sh
curl -s http://127.0.0.1:8000/health
curl -s http://127.0.0.1:8000/.well-known/oauth-authorization-server
# Bearer 無しは 401 + WWW-Authenticate
curl -si -X POST http://127.0.0.1:8000/mcp/v3 \
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
| `CLAUDE_MCP_COMMAND` | 既定 `claude mcp serve` |
| `CLAUDE_CWD` | stdio 子プロセスの cwd（省略時 `$HOME`） |

## これから

1. ~~GitHub OAuth + bearer~~ ← 済
2. `StdioMcpBackend` の本格 stdio JSON-RPC ブリッジ
3. duxca VPC（GCP）へ移設し、Tunnel コネクタをそこへ

## 開発メモ

- webrtc.duxca.com / river.duxca.com と同じく Axum 0.8 + envy + tracing。
- CIMD 取得は公開 IP だけに接続する。ローカル DNS が合成アドレスを返すときは Cloudflare DoH にフォールバックする。
- ループバック redirect（`http://localhost/callback`）は RFC 8252 どおりポート違いを許す。
