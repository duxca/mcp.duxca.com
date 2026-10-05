# mcp.duxca.com

Grok / Claude アプリから呼べる **MCP ゲートウェイ**（Rust / Axum）。

参考実装は pascal 上の `~/Github/mcp-test`（Python / Starlette）。
本番は `mcp.duxca.com` を **Cloudflare Tunnel** で公開し、バックエンドは差し替え可能にする。

## アーキテクチャ（想定）

```
[Grok / Claude クラウド]
        │ HTTPS
        ▼
 Cloudflare Tunnel  ──►  mcp.duxca.com ゲートウェイ (Axum)
                              │
                              ├─ GitHub OAuth + allowlist（数値 id）
                              ├─ 自前 Bearer で POST /mcp/v3 を保護
                              └─ McpBackend トレイト
                                    ├─ StdioMcpBackend（claude mcp serve）← いまの骨格
                                    └─ （将来）HTTP MCP など差し替え
```

- 公開 URL はアプリ側が直接見る HTTPS オリジンだけ（スマホ→自宅直結ではない）。
- 許可アカウントは GitHub **数値 id**（login は改名で再利用されうる）。既定: `2429307`（legokichi）。
- MCP は JSON-RPC 1 本（`POST /mcp/v3`）。SSE 必須ではない。

## ルート（骨格）

| Method | Path | 説明 |
|--------|------|------|
| GET | `/` | 案内テキスト |
| GET | `/health` | 生存確認 JSON |
| POST | `/mcp/v3` | MCP JSON-RPC（Bearer 必須・骨格） |
| GET | `/github/callback` | GitHub OAuth コールバック（未実装プレースホルダ） |
| GET | `/github/setup` | OAuth 未設定時の案内 |

## ローカル起動

```sh
cp .env.example .env
# 必要なら GITHUB_* を埋める。ローカルは PUBLIC_URL=http://127.0.0.1:8000 で可。

cargo run
# または
PUBLIC_URL=http://127.0.0.1:8000 PORT=8000 cargo run
```

確認:

```sh
curl -s http://127.0.0.1:8000/health
curl -s -X POST http://127.0.0.1:8000/mcp/v3 \
  -H 'Authorization: Bearer dummy' \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"curl","version":"0"}}}'
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

## これから（本番）

1. GitHub OAuth 本実装（認可コード交換・allowlist・bearer 発行）— mcp-test の `auth.py` 相当
2. `StdioMcpBackend` の本格 stdio JSON-RPC ブリッジ（initialize / tools/list / tools/call）
3. **duxca VPC**（GCP `duxca-298210`）に配置
4. **named Cloudflare Tunnel** で `mcp.duxca.com` を固定公開（quick tunnel は使わない）
5. GitHub リポジトリ `duxca/mcp.duxca.com` への push・CI / Deploy（指示が出てから）

DNS・トンネル・リモート push はこのリポの骨格段階では行わない。

## 開発メモ

- webrtc.duxca.com / river.duxca.com と同じく Axum 0.8 + envy + tracing。
- バックエンド差し替えは `McpBackend` トレイト経由。
