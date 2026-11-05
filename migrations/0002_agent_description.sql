-- スキーマ v2: register_agent の任意の自己紹介（役割）。list_agents で公開する。NULL なら未設定。
ALTER TABLE relay_agents ADD COLUMN description TEXT;
