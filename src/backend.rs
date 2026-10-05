//! 差し替え可能な MCP バックエンド。

use async_trait::async_trait;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use tokio::process::Command;
use tokio::sync::Mutex;

/// JSON-RPC 1 本を処理するバックエンド。
#[async_trait]
pub trait McpBackend: Send + Sync {
    async fn handle(&self, message: Value) -> Option<Value>;
}

/// パス (`/name/version`) → バックエンド。
pub type BackendRegistry = HashMap<String, Arc<dyn McpBackend>>;

/// `claude mcp serve` など stdio JSON-RPC プロセスへの橋渡し（骨格）。
///
/// いまはプロセス起動と健全性チェック程度。本格的な request/response 対応は後続。
pub struct StdioMcpBackend {
    /// 表示用（serverInfo.name）。未設定なら mcp.duxca.com。
    service_name: String,
    command: Vec<String>,
    cwd: PathBuf,
    inner: Mutex<StdioState>,
}

struct StdioState {
    /// 子プロセスが生きていれば Some。骨格段階では通信は未実装。
    child: Option<tokio::process::Child>,
}

impl StdioMcpBackend {
    #[allow(dead_code)]
    pub fn new(command: Vec<String>, cwd: PathBuf) -> Arc<Self> {
        Self::named("mcp.duxca.com", command, cwd)
    }

    pub fn named(service_name: impl Into<String>, command: Vec<String>, cwd: PathBuf) -> Arc<Self> {
        Arc::new(Self {
            service_name: service_name.into(),
            command,
            cwd,
            inner: Mutex::new(StdioState { child: None }),
        })
    }

    fn stub_error(id: Option<Value>, message: &str) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": -32000,
                "message": message,
            }
        })
    }

    async fn ensure_started(&self) -> Result<(), String> {
        let mut state = self.inner.lock().await;
        if let Some(child) = state.child.as_mut() {
            match child.try_wait() {
                Ok(None) => return Ok(()),
                Ok(Some(status)) => {
                    tracing::warn!(?status, "stdio MCP child exited; restarting");
                    state.child = None;
                }
                Err(err) => {
                    tracing::warn!(%err, "failed to poll stdio MCP child");
                    state.child = None;
                }
            }
        }

        if self.command.is_empty() {
            return Err("MCP command is empty".into());
        }

        let mut cmd = Command::new(&self.command[0]);
        if self.command.len() > 1 {
            cmd.args(&self.command[1..]);
        }
        cmd.current_dir(&self.cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        match cmd.spawn() {
            Ok(child) => {
                tracing::info!(
                    service = %self.service_name,
                    command = %self.command.join(" "),
                    cwd = %self.cwd.display(),
                    "spawned stdio MCP backend"
                );
                state.child = Some(child);
                Ok(())
            }
            Err(err) => Err(format!(
                "failed to spawn {:?}: {err} (skeleton may run without Claude installed)",
                self.command
            )),
        }
    }
}

#[async_trait]
impl McpBackend for StdioMcpBackend {
    async fn handle(&self, message: Value) -> Option<Value> {
        let id = message.get("id").cloned();
        let method = message.get("method").and_then(|m| m.as_str()).unwrap_or("");

        // 通知は応答しない
        if method.starts_with("notifications/") {
            return None;
        }

        if method == "ping" {
            return Some(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {}
            }));
        }

        // initialize / server/discover はプロセス無しでも骨格応答を返す
        if method == "initialize" || method == "server/discover" {
            let version = message
                .pointer("/params/protocolVersion")
                .and_then(|v| v.as_str())
                .unwrap_or("2025-03-26");
            return Some(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "protocolVersion": version,
                    "capabilities": { "tools": {} },
                    "serverInfo": {
                        "name": self.service_name,
                        "version": env!("CARGO_PKG_VERSION"),
                    },
                    "instructions": "骨格段階。stdio バックエンドの本実装はこれから。",
                    "supportedVersions": ["2026-07-28", "2025-03-26"],
                }
            }));
        }

        match self.ensure_started().await {
            Ok(()) => Some(Self::stub_error(
                id,
                "stdio JSON-RPC bridge not fully implemented yet",
            )),
            Err(err) => Some(Self::stub_error(id, &err)),
        }
    }
}
