-- スキーマ v3: セキュリティレビュー（2026-11-11）の H-1 / L-3 / L-6。

-- H-1: 認可を始めたブラウザ（Cookie のハッシュ）。callback で一致を必須にする。NULL の行（v2 の途中）は通らない
ALTER TABLE oauth_pending ADD COLUMN browser_sha256 TEXT;

-- H-1: 同意画面で承認され、許可された GitHub ログインまで済んだ組。次回からは同意画面を出さない
CREATE TABLE oauth_consents (
  client_id    TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,      -- ループバックはポートを除いた形
  subject      TEXT NOT NULL,      -- 承認した GitHub 数値 id
  approved_at  INTEGER NOT NULL,
  PRIMARY KEY (client_id, redirect_uri, subject)
) STRICT;

-- L-3: 認可 1 回ごとの系列（grant_id）と、その開始時刻（絶対期限の起点）。
-- refresh は使っても消さずに used_at を付け、期限まで再利用の検知に使う
ALTER TABLE oauth_tokens ADD COLUMN grant_id TEXT;
ALTER TABLE oauth_tokens ADD COLUMN granted_at INTEGER;
ALTER TABLE oauth_tokens ADD COLUMN used_at INTEGER;
UPDATE oauth_tokens SET grant_id = token_sha256, granted_at = issued_at WHERE kind = 'refresh';
UPDATE oauth_tokens SET grant_id = (
  SELECT r.grant_id FROM oauth_tokens r
  WHERE r.kind = 'refresh' AND r.access_sha256 = oauth_tokens.token_sha256
) WHERE kind = 'access';
UPDATE oauth_tokens SET grant_id = token_sha256 WHERE grant_id IS NULL;
UPDATE oauth_tokens SET granted_at = issued_at WHERE granted_at IS NULL;
CREATE INDEX oauth_tokens_client ON oauth_tokens (client_id, subject);
CREATE INDEX oauth_tokens_grant ON oauth_tokens (grant_id);

-- L-3: 使ったコードも期限まで残し、2 回目の使用で発行済みトークンを失効させる
ALTER TABLE oauth_codes ADD COLUMN used_at INTEGER;

-- L-6: 登録した OAuth クライアント。NULL（v2 までの登録）は次に登録したクライアントのものになる
ALTER TABLE relay_agents ADD COLUMN client_id TEXT;
-- L-6: 0 なら webhook の本文に text と添付を載せない（受け手は check_messages で取りに来る）
ALTER TABLE relay_agents ADD COLUMN webhook_include_text INTEGER NOT NULL DEFAULT 1;
