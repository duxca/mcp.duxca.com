-- スキーマ v1（設計書 §5.2）。auto_vacuum と user_version は src/db.rs が設定する。

-- ---------------------------------------------------------------- OAuth
CREATE TABLE oauth_clients (
  client_id     TEXT PRIMARY KEY,
  secret_sha256 TEXT,              -- token_endpoint_auth_method = none なら NULL
  record        TEXT NOT NULL,     -- ClientRecord の JSON（client_secret は入れない）
  registered_at INTEGER NOT NULL   -- Unix 秒。MAX_CLIENTS を超えたら古い順に消す
) STRICT;

CREATE TABLE oauth_pending (       -- /authorize → GitHub → callback の間
  state_sha256 TEXT PRIMARY KEY,
  client_id    TEXT NOT NULL,
  params       TEXT NOT NULL,      -- AuthorizationParams の JSON
  expires_at   INTEGER NOT NULL
) STRICT;

CREATE TABLE oauth_codes (
  code_sha256    TEXT PRIMARY KEY,
  client_id      TEXT NOT NULL,
  subject        TEXT NOT NULL,    -- GitHub 数値 id
  resource       TEXT NOT NULL,
  scopes         TEXT NOT NULL,    -- JSON 配列
  code_challenge TEXT NOT NULL,
  redirect_uri   TEXT NOT NULL,
  redirect_uri_provided_explicitly INTEGER NOT NULL,
  expires_at     INTEGER NOT NULL
) STRICT;

CREATE TABLE oauth_tokens (
  token_sha256  TEXT PRIMARY KEY,
  kind          TEXT NOT NULL CHECK (kind IN ('access', 'refresh')),
  client_id     TEXT NOT NULL,
  subject       TEXT NOT NULL,
  resource      TEXT NOT NULL,
  scopes        TEXT NOT NULL,     -- JSON 配列
  issued_at     INTEGER NOT NULL,
  expires_at    INTEGER NOT NULL,
  access_sha256 TEXT               -- refresh の行だけ持つ。対になる access
) STRICT;
CREATE INDEX oauth_tokens_expiry ON oauth_tokens (expires_at);

-- ---------------------------------------------------------------- relay
CREATE TABLE relay_rooms (
  room    TEXT PRIMARY KEY,        -- OAuth の subject
  next_id INTEGER NOT NULL         -- 次のメッセージ id。部屋を最初に使った時刻の Unix ミリ秒から始める
) STRICT;

CREATE TABLE relay_threads (
  room       TEXT NOT NULL,
  id         TEXT NOT NULL,        -- thr_<hex>
  subject    TEXT NOT NULL,
  started_by TEXT NOT NULL,
  created_at INTEGER NOT NULL,     -- Unix ミリ秒
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (room, id)
) STRICT;

CREATE TABLE relay_messages (
  room           TEXT NOT NULL,
  id             INTEGER NOT NULL, -- = cursor
  thread_id      TEXT NOT NULL,
  sender         TEXT NOT NULL,    -- API の from
  recipient      TEXT NOT NULL,    -- API の to
  text           TEXT NOT NULL,
  created_at     INTEGER NOT NULL,
  read_at        INTEGER,
  webhook_status TEXT,             -- 内部の記録。API には出さない
  data_bytes     INTEGER NOT NULL, -- 保存量の見積もり
  PRIMARY KEY (room, id),
  FOREIGN KEY (room, thread_id) REFERENCES relay_threads (room, id) ON DELETE CASCADE
) STRICT;
CREATE INDEX relay_messages_inbox  ON relay_messages (room, recipient, id);
CREATE INDEX relay_messages_unread ON relay_messages (room, recipient) WHERE read_at IS NULL;
CREATE INDEX relay_messages_thread ON relay_messages (room, thread_id, id);
CREATE INDEX relay_messages_age    ON relay_messages (created_at);

CREATE TABLE relay_attachments (
  room         TEXT NOT NULL,
  id           TEXT NOT NULL,      -- att_<hex>
  message_id   INTEGER NOT NULL,
  position     INTEGER NOT NULL,   -- メッセージの中での順番
  filename     TEXT NOT NULL,
  content_type TEXT NOT NULL,
  size         INTEGER NOT NULL,
  sha256       TEXT NOT NULL,
  data         BLOB NOT NULL,      -- 最後の列に置く。メタデータだけを読む問い合わせが overflow ページを読まずに済む
  PRIMARY KEY (room, id),
  FOREIGN KEY (room, message_id) REFERENCES relay_messages (room, id) ON DELETE CASCADE
) STRICT;
CREATE INDEX relay_attachments_message ON relay_attachments (room, message_id, position);

CREATE TABLE relay_agents (
  room           TEXT NOT NULL,
  name           TEXT NOT NULL,
  webhook_url    TEXT,
  webhook_auth   TEXT,             -- 平文（U4）。どの API からも読み返せない
  webhook_secret TEXT,             -- 平文（U4）
  data_bytes     INTEGER NOT NULL, -- agent_bytes()
  PRIMARY KEY (room, name)
) STRICT;
