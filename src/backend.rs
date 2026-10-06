//! 差し替え可能な MCP バックエンド。
//!
//! `StdioMcpBackend` は stdio の JSON-RPC MCP サーバ（`claude mcp serve`、
//! `codex mcp-server`、`adbmcp` など）を 1 本だけ常駐させ、HTTP から来た
//! JSON-RPC を行区切りで中継する。

use async_trait::async_trait;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::Mutex;

/// JSON-RPC 1 本を処理するバックエンド。
#[async_trait]
pub trait McpBackend: Send + Sync {
    async fn handle(&self, message: Value) -> Option<Value>;
}

/// パス (`/name/version`) → バックエンド。
pub type BackendRegistry = HashMap<String, Arc<dyn McpBackend>>;

const DEFAULT_PROTOCOL: &str = "2025-03-26";

/// stdio JSON-RPC プロセスへの橋渡し。
///
/// - 子プロセスは初回リクエストで起動し、ゲートウェイ自身が initialize を済ませる。
/// - クライアントの `initialize` にはキャッシュした結果を返す。
/// - それ以外のリクエストは内部 id に付け替えて中継し、応答の id を元に戻す。
/// - 子が落ちていたら次のリクエストで起動し直す。
/// - リクエストは直列に処理する（1 本ずつ）。
pub struct StdioMcpBackend {
    service_name: String,
    command: Vec<String>,
    cwd: PathBuf,
    timeout: Duration,
    inner: Mutex<StdioState>,
}

struct Running {
    child: Child,
    stdin: ChildStdin,
    stdout: Lines<BufReader<ChildStdout>>,
    init_result: Value,
}

struct StdioState {
    running: Option<Running>,
    next_id: u64,
}

impl StdioMcpBackend {
    #[allow(dead_code)]
    pub fn new(command: Vec<String>, cwd: PathBuf) -> Arc<Self> {
        Self::named("mcp.duxca.com", command, cwd)
    }

    pub fn named(service_name: impl Into<String>, command: Vec<String>, cwd: PathBuf) -> Arc<Self> {
        let secs = std::env::var("MCP_REQUEST_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(600);
        Self::with_timeout(service_name, command, cwd, Duration::from_secs(secs))
    }

    pub fn with_timeout(
        service_name: impl Into<String>,
        command: Vec<String>,
        cwd: PathBuf,
        timeout: Duration,
    ) -> Arc<Self> {
        Arc::new(Self {
            service_name: service_name.into(),
            command,
            cwd,
            timeout,
            inner: Mutex::new(StdioState {
                running: None,
                next_id: 1,
            }),
        })
    }

    fn error(id: Option<Value>, code: i64, message: &str) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": { "code": code, "message": message }
        })
    }

    /// 子へ 1 行書き、`want_id` の応答が来るまで読む。
    /// 子からのサーバ発リクエストには method not found を返し、通知は捨てる。
    async fn roundtrip(
        running: &mut Running,
        msg: &Value,
        want_id: &Value,
        timeout: Duration,
    ) -> Result<Value, String> {
        let mut line = serde_json::to_string(msg).map_err(|e| e.to_string())?;
        line.push('\n');
        running
            .stdin
            .write_all(line.as_bytes())
            .await
            .map_err(|e| format!("write to child: {e}"))?;
        running
            .stdin
            .flush()
            .await
            .map_err(|e| format!("flush: {e}"))?;

        let fut = async {
            loop {
                let next = running
                    .stdout
                    .next_line()
                    .await
                    .map_err(|e| format!("read from child: {e}"))?;
                let Some(raw) = next else {
                    return Err("child closed stdout".to_string());
                };
                let raw = raw.trim();
                if raw.is_empty() {
                    continue;
                }
                let Ok(v) = serde_json::from_str::<Value>(raw) else {
                    tracing::debug!(line = %raw, "non-JSON line from child");
                    continue;
                };
                let has_method = v.get("method").is_some();
                match (v.get("id"), has_method) {
                    (Some(id), false) if id == want_id => return Ok(v),
                    (Some(id), true) => {
                        // サーバ発リクエスト（roots/list, sampling など）は未対応
                        let reply =
                            Self::error(Some(id.clone()), -32601, "not supported by gateway");
                        let mut l = serde_json::to_string(&reply).unwrap_or_default();
                        l.push('\n');
                        let _ = running.stdin.write_all(l.as_bytes()).await;
                        let _ = running.stdin.flush().await;
                    }
                    _ => {} // 通知・無関係な応答
                }
            }
        };
        match tokio::time::timeout(timeout, fut).await {
            Ok(r) => r,
            Err(_) => Err(format!("timeout after {}s", timeout.as_secs())),
        }
    }

    async fn start(&self, state: &mut StdioState) -> Result<(), String> {
        if let Some(r) = state.running.as_mut() {
            match r.child.try_wait() {
                Ok(None) => return Ok(()),
                Ok(Some(status)) => {
                    tracing::warn!(service = %self.service_name, ?status, "stdio MCP child exited; restarting")
                }
                Err(err) => {
                    tracing::warn!(service = %self.service_name, %err, "poll child failed; restarting")
                }
            }
            state.running = None;
        }
        if self.command.is_empty() {
            return Err("MCP command is empty".into());
        }
        let mut cmd = Command::new(&self.command[0]);
        cmd.args(&self.command[1..])
            .current_dir(&self.cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true);
        let mut child = cmd
            .spawn()
            .map_err(|e| format!("failed to spawn {:?}: {e}", self.command))?;
        let stdin = child.stdin.take().ok_or("no stdin")?;
        let stdout = BufReader::new(child.stdout.take().ok_or("no stdout")?).lines();
        tracing::info!(service = %self.service_name, command = %self.command.join(" "), cwd = %self.cwd.display(), "spawned stdio MCP backend");

        let mut running = Running {
            child,
            stdin,
            stdout,
            init_result: Value::Null,
        };
        let id = json!(format!("gw-init-{}", state.next_id));
        state.next_id += 1;
        let init = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "initialize",
            "params": {
                "protocolVersion": DEFAULT_PROTOCOL,
                "capabilities": {},
                "clientInfo": { "name": "mcp.duxca.com", "version": env!("CARGO_PKG_VERSION") }
            }
        });
        let reply = Self::roundtrip(
            &mut running,
            &init,
            &id,
            self.timeout.min(Duration::from_secs(60)),
        )
        .await?;
        let Some(result) = reply.get("result").cloned() else {
            return Err(format!(
                "initialize failed: {}",
                reply.get("error").cloned().unwrap_or(Value::Null)
            ));
        };
        let mut l =
            serde_json::to_string(&json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
                .unwrap();
        l.push('\n');
        running
            .stdin
            .write_all(l.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        running.stdin.flush().await.map_err(|e| e.to_string())?;
        running.init_result = result;
        state.running = Some(running);
        Ok(())
    }
}

#[async_trait]
impl McpBackend for StdioMcpBackend {
    async fn handle(&self, message: Value) -> Option<Value> {
        let id = message.get("id").cloned();
        let method = message
            .get("method")
            .and_then(|m| m.as_str())
            .unwrap_or("")
            .to_string();

        // クライアント側の通知はゲートウェイで吸収する（子は初期化済み）
        if method.starts_with("notifications/") || id.is_none() {
            return None;
        }
        if method == "ping" {
            return Some(json!({ "jsonrpc": "2.0", "id": id, "result": {} }));
        }

        let mut state = self.inner.lock().await;
        if let Err(err) = self.start(&mut state).await {
            state.running = None;
            return Some(Self::error(id, -32000, &err));
        }

        if method == "initialize" {
            let mut result = state.running.as_ref().unwrap().init_result.clone();
            if let Some(v) = message.pointer("/params/protocolVersion").cloned() {
                // 子が古い版で答えていても、クライアントの版をそのまま返す方が互換性が高い
                if result.get("protocolVersion").is_none() {
                    result["protocolVersion"] = v;
                }
            }
            return Some(json!({ "jsonrpc": "2.0", "id": id, "result": result }));
        }

        let internal = json!(format!("gw-{}", state.next_id));
        state.next_id += 1;
        let mut forwarded = message.clone();
        forwarded["id"] = internal.clone();
        let running = state.running.as_mut().unwrap();
        match Self::roundtrip(running, &forwarded, &internal, self.timeout).await {
            Ok(mut reply) => {
                reply["id"] = id.unwrap_or(Value::Null);
                Some(reply)
            }
            Err(err) => {
                tracing::warn!(service = %self.service_name, %err, "stdio bridge failed; dropping child");
                state.running = None;
                Some(Self::error(id, -32000, &err))
            }
        }
    }
}

#[cfg(test)]
mod bridge_tests {
    use super::*;

    /// python3 で書いた最小 MCP サーバ（initialize / tools/list / サーバ発リクエスト / 通知）。
    fn fake_server() -> Vec<String> {
        let script = r#"
import sys, json
for line in sys.stdin:
    m = json.loads(line)
    if 'id' not in m:
        continue
    if m['method'] == 'initialize':
        r = {'protocolVersion':'2025-03-26','capabilities':{'tools':{}},'serverInfo':{'name':'fake','version':'1'}}
    elif m['method'] == 'tools/list':
        print(json.dumps({'jsonrpc':'2.0','method':'notifications/message','params':{}}), flush=True)
        print(json.dumps({'jsonrpc':'2.0','id':'srv-1','method':'roots/list'}), flush=True)
        sys.stdin.readline()
        r = {'tools':[{'name':'echo','inputSchema':{'type':'object'}}]}
    elif m['method'] == 'die':
        sys.exit(0)
    else:
        print(json.dumps({'jsonrpc':'2.0','id':m['id'],'error':{'code':-32601,'message':'nope'}}), flush=True)
        continue
    print(json.dumps({'jsonrpc':'2.0','id':m['id'],'result':r}), flush=True)
"#;
        vec!["python3".into(), "-c".into(), script.into()]
    }

    fn backend() -> Arc<StdioMcpBackend> {
        StdioMcpBackend::with_timeout(
            "fake/v1",
            fake_server(),
            std::env::temp_dir(),
            Duration::from_secs(10),
        )
    }

    #[tokio::test]
    async fn initialize_and_tools_list_roundtrip() {
        let b = backend();
        let init = b
            .handle(json!({"jsonrpc":"2.0","id":7,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}))
            .await
            .unwrap();
        assert_eq!(init["id"], 7);
        assert_eq!(init["result"]["serverInfo"]["name"], "fake");

        assert!(b
            .handle(json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
            .await
            .is_none());

        let list = b
            .handle(json!({"jsonrpc":"2.0","id":"abc","method":"tools/list"}))
            .await
            .unwrap();
        assert_eq!(list["id"], "abc");
        assert_eq!(list["result"]["tools"][0]["name"], "echo");
    }

    #[tokio::test]
    async fn error_passthrough_and_restart_after_exit() {
        let b = backend();
        let e = b
            .handle(json!({"jsonrpc":"2.0","id":1,"method":"unknown"}))
            .await
            .unwrap();
        assert_eq!(e["error"]["code"], -32601);
        assert_eq!(e["id"], 1);

        let d = b
            .handle(json!({"jsonrpc":"2.0","id":2,"method":"die"}))
            .await
            .unwrap();
        assert_eq!(d["error"]["code"], -32000);

        let list = b
            .handle(json!({"jsonrpc":"2.0","id":3,"method":"tools/list"}))
            .await
            .unwrap();
        assert_eq!(list["result"]["tools"][0]["name"], "echo");
    }

    #[tokio::test]
    async fn spawn_failure_is_jsonrpc_error() {
        let b = StdioMcpBackend::with_timeout(
            "x/v1",
            vec!["/nonexistent/bin".into()],
            std::env::temp_dir(),
            Duration::from_secs(2),
        );
        let e = b
            .handle(json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}))
            .await
            .unwrap();
        assert_eq!(e["error"]["code"], -32000);
    }
}
