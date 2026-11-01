//! SQLite の 1 ファイル（`DATABASE_PATH`）。OAuth と relay のストアが 1 本の接続を共有する。
//!
//! 呼び出しは同期で、ロックは `.await` をまたいで持たない。書き込みは 1 メソッド 1 トランザクション
//! （`BEGIN IMMEDIATE`）。スキーマは埋め込みの SQL と `PRAGMA user_version` で前進だけさせる。

use rusqlite::{Connection, Transaction, TransactionBehavior};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

/// `user_version` は適用済みの数。足すときは末尾に追加する（適用済みの SQL は書き換えない）。
const MIGRATIONS: &[&str] = &[include_str!("../migrations/0001_init.sql")];

/// DB の失敗。HTTP では 503 にする（401 や invalid_grant にすると、クライアントに再認可を促してしまう）。
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct DbError(#[from] rusqlite::Error);

#[derive(Clone)]
pub struct Db(Arc<Mutex<Connection>>);

impl Db {
    /// `wal_autocheckpoint` が None なら SQLite の既定のまま（VM）。Litestream と組むときは 0 にする。
    pub fn open(path: &str, wal_autocheckpoint: Option<u32>) -> anyhow::Result<Self> {
        Self::init(Connection::open(path)?, wal_autocheckpoint)
    }

    #[cfg(test)]
    pub fn open_in_memory() -> Self {
        Self::init(Connection::open_in_memory().unwrap(), None).unwrap()
    }

    fn init(mut conn: Connection, wal_autocheckpoint: Option<u32>) -> anyhow::Result<Self> {
        conn.busy_timeout(Duration::from_secs(5))?;
        let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        let known = MIGRATIONS.len() as i64;
        anyhow::ensure!(
            version <= known,
            "database schema is v{version}, newer than this binary (v{known}); refusing to start"
        );
        if version == 0 {
            // 表を作る前でないと効かない
            conn.pragma_update(None, "auto_vacuum", "INCREMENTAL")?;
        }
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", true)?;
        if let Some(pages) = wal_autocheckpoint {
            conn.pragma_update(None, "wal_autocheckpoint", pages)?;
        }
        for (i, sql) in MIGRATIONS.iter().enumerate().skip(version as usize) {
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute_batch(sql)?;
            tx.pragma_update(None, "user_version", i as i64 + 1)?;
            tx.commit()?;
        }
        Ok(Self(Arc::new(Mutex::new(conn))))
    }

    fn lock(&self) -> MutexGuard<'_, Connection> {
        // 書きかけのトランザクションは Transaction の drop でロールバックされるので、毒は無視してよい
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// 読むだけ。接続は 1 本でロックを持ったまま読むので、複数の文でも一貫する。
    pub fn read<T>(
        &self,
        f: impl FnOnce(&Connection) -> rusqlite::Result<T>,
    ) -> rusqlite::Result<T> {
        f(&self.lock())
    }

    /// `BEGIN IMMEDIATE` から `COMMIT` まで。`f` が Err ならロールバックする。
    pub fn write<T, E: From<rusqlite::Error>>(
        &self,
        f: impl FnOnce(&Transaction) -> Result<T, E>,
    ) -> Result<T, E> {
        let mut conn = self.lock();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let out = f(&tx)?;
        tx.commit()?;
        Ok(out)
    }
}

/// テスト用の DB ファイル（`-wal` と `-shm` も含めて drop で消す）。
#[cfg(test)]
pub struct TempPath(pub String);

#[cfg(test)]
impl TempPath {
    pub fn new(name: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("mcp-{name}-{}-{nanos}.db", std::process::id()));
        Self(path.to_string_lossy().into_owned())
    }

    /// 本体と WAL の中身（平文が残っていないかを見る）。
    pub fn bytes(&self) -> Vec<u8> {
        ["", "-wal"]
            .iter()
            .flat_map(|suffix| std::fs::read(format!("{}{suffix}", self.0)).unwrap_or_default())
            .collect()
    }
}

#[cfg(test)]
impl Drop for TempPath {
    fn drop(&mut self) {
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", self.0));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opens_with_the_designed_pragmas_and_refuses_a_newer_schema() {
        let path = TempPath::new("pragmas");
        let path = &path.0;
        let db = Db::open(path, None).unwrap();
        db.read(|c| {
            let get = |name: &str| -> rusqlite::Result<String> {
                c.pragma_query_value(None, name, |r| r.get::<_, rusqlite::types::Value>(0))
                    .map(|v| format!("{v:?}"))
            };
            assert_eq!(get("journal_mode")?, "Text(\"wal\")");
            assert_eq!(get("synchronous")?, "Integer(1)"); // NORMAL
            assert_eq!(get("foreign_keys")?, "Integer(1)");
            assert_eq!(get("busy_timeout")?, "Integer(5000)");
            assert_eq!(get("auto_vacuum")?, "Integer(2)"); // INCREMENTAL
            assert_eq!(get("wal_autocheckpoint")?, "Integer(1000)"); // SQLite の既定
            assert_eq!(get("user_version")?, "Integer(1)");
            Ok(())
        })
        .unwrap();
        drop(db);

        // 開き直しても適用し直さない
        let db = Db::open(path, Some(0)).unwrap();
        let checkpoint: i64 = db
            .read(|c| c.pragma_query_value(None, "wal_autocheckpoint", |r| r.get(0)))
            .unwrap();
        assert_eq!(checkpoint, 0);
        db.read(|c| c.pragma_update(None, "user_version", 2))
            .unwrap();
        drop(db);
        let err = Db::open(path, None).err().unwrap().to_string();
        assert!(err.contains("newer than this binary"), "{err}");
    }
}
