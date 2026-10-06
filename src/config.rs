//! 環境変数からの設定。

use crate::auth::RedirectAllowlist;
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

/// 1 つの MCP サービス（パス `/{name}/{version}`）。
#[derive(Debug, Clone)]
pub struct ServiceConfig {
    pub name: String,
    pub version: String,
    pub command: Vec<String>,
    pub cwd: PathBuf,
    /// `/{name}/{version}`
    pub path: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct Config {
    /// 公開オリジン（スキーム+ホスト。末尾スラッシュなし）。例: https://mcp.duxca.com
    #[serde(default = "default_public_url")]
    pub public_url: String,

    /// 待受アドレス。公開は Cloudflare Tunnel 経由なので既定はループバック。
    #[serde(default = "default_bind_addr")]
    pub bind_addr: String,

    #[serde(default = "default_port")]
    pub port: u16,

    /// カンマ区切りの redirect_uri allowlist。未設定なら auth::DEFAULT_REDIRECT_ALLOWLIST。
    #[serde(default)]
    pub oauth_redirect_allowlist: Option<String>,

    #[serde(default)]
    pub github_client_id: String,

    #[serde(default)]
    pub github_client_secret: String,

    /// カンマ区切りの GitHub 数値 id。login は改名で再利用されうるので使わない。
    #[serde(default = "default_allowed_ids")]
    pub allowed_github_ids: String,

    /// カンマ区切りの `name/version`。空なら `default/v1` + CLAUDE_MCP_COMMAND。
    #[serde(default)]
    pub mcp_services: String,

    /// 互換フォールバック用（MCP_SERVICES 未設定時の default/v1）。
    #[serde(default = "default_claude_command")]
    pub claude_mcp_command: String,

    #[serde(default)]
    pub claude_cwd: Option<String>,
}

fn default_public_url() -> String {
    "http://127.0.0.1:8000".into()
}

fn default_bind_addr() -> String {
    "127.0.0.1".into()
}

fn default_port() -> u16 {
    8000
}

fn default_allowed_ids() -> String {
    "2429307".into()
}

fn default_claude_command() -> String {
    "claude mcp serve".into()
}

/// `name` / `version` を環境変数キー用に正規化する。
/// 例: `claude/v1` → `CLAUDE_V1`（接頭辞は呼び出し側で付ける）。
pub fn env_key_suffix(name: &str, version: &str) -> String {
    let mut out = String::with_capacity(name.len() + version.len() + 1);
    for (i, part) in [name, version].into_iter().enumerate() {
        if i > 0 {
            out.push('_');
        }
        for c in part.chars() {
            if c.is_ascii_alphanumeric() {
                out.push(c.to_ascii_uppercase());
            } else {
                out.push('_');
            }
        }
    }
    out
}

/// サービス名: `[a-z0-9]` または `[a-z0-9]([a-z0-9-]*[a-z0-9])?`
pub fn valid_service_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 64 {
        return false;
    }
    if name.contains("..") || name.contains('/') || name.contains('\\') {
        return false;
    }
    let bytes = name.as_bytes();
    if !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit() {
        return false;
    }
    if bytes.len() == 1 {
        return true;
    }
    if !bytes[bytes.len() - 1].is_ascii_lowercase() && !bytes[bytes.len() - 1].is_ascii_digit() {
        return false;
    }
    bytes[1..bytes.len() - 1]
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
}

/// バージョン: `v` + 1 つ以上の数字（例: v1, v2, v10）。
pub fn valid_version(version: &str) -> bool {
    if version.len() < 2 || version.len() > 16 {
        return false;
    }
    let mut chars = version.chars();
    if chars.next() != Some('v') {
        return false;
    }
    let rest: String = chars.collect();
    !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit())
}

fn split_command(raw: &str) -> Vec<String> {
    raw.split_whitespace().map(str::to_string).collect()
}

fn default_cwd(claude_cwd: &Option<String>) -> PathBuf {
    claude_cwd.as_ref().map(PathBuf::from).unwrap_or_else(|| {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."))
    })
}

impl Config {
    pub fn from_env() -> Result<Self, envy::Error> {
        envy::from_env::<Self>()
    }

    pub fn allowed_ids(&self) -> HashSet<String> {
        self.allowed_github_ids
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    }

    pub fn listen_addr(&self) -> anyhow::Result<SocketAddr> {
        let ip: IpAddr =
            self.bind_addr.trim().parse().map_err(|_| {
                anyhow::anyhow!("BIND_ADDR は IP アドレスにする: {}", self.bind_addr)
            })?;
        Ok(SocketAddr::new(ip, self.port))
    }

    pub fn redirect_allowlist(&self) -> anyhow::Result<RedirectAllowlist> {
        match self
            .oauth_redirect_allowlist
            .as_deref()
            .filter(|s| !s.trim().is_empty())
        {
            None => Ok(RedirectAllowlist::default()),
            Some(raw) => RedirectAllowlist::parse(raw.split(','))
                .map_err(|e| anyhow::anyhow!("OAUTH_REDIRECT_ALLOWLIST: {e}")),
        }
    }

    pub fn normalize_public_url(&self) -> anyhow::Result<String> {
        let value = self.public_url.trim().trim_end_matches('/').to_string();
        let Some((scheme, rest)) = value.split_once("://") else {
            anyhow::bail!("PUBLIC_URL はスキームとホストだけにする");
        };
        if rest.is_empty() || rest.contains('/') || rest.contains('?') || rest.contains('#') {
            anyhow::bail!("PUBLIC_URL はスキームとホストだけにする");
        }
        let host = rest.split(':').next().unwrap_or(rest);
        if scheme != "https" && host != "localhost" && host != "127.0.0.1" {
            anyhow::bail!("PUBLIC_URL は HTTPS にする（localhost 以外）");
        }
        Ok(value)
    }

    /// `MCP_SERVICES` からサービス一覧を組み立てる。空なら `default/v1`。
    pub fn services(&self) -> anyhow::Result<Vec<ServiceConfig>> {
        let entries: Vec<&str> = self
            .mcp_services
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();

        if entries.is_empty() {
            let command = split_command(&self.claude_mcp_command);
            if command.is_empty() {
                anyhow::bail!("CLAUDE_MCP_COMMAND が空（MCP_SERVICES 未設定時のフォールバック）");
            }
            return Ok(vec![ServiceConfig {
                name: "default".into(),
                version: "v1".into(),
                command,
                cwd: default_cwd(&self.claude_cwd),
                path: "/default/v1".into(),
            }]);
        }

        let mut out = Vec::with_capacity(entries.len());
        let mut seen = HashSet::new();
        for entry in entries {
            let Some((name, version)) = entry.split_once('/') else {
                anyhow::bail!("MCP_SERVICES の項目は name/version 形式: {entry}");
            };
            let name = name.trim();
            let version = version.trim();
            if name.is_empty() || version.is_empty() || version.contains('/') {
                anyhow::bail!("MCP_SERVICES の項目が不正: {entry}");
            }
            if !valid_service_name(name) {
                anyhow::bail!("サービス名が不正: {name}");
            }
            if !valid_version(version) {
                anyhow::bail!("バージョンが不正（v + 数字）: {version}");
            }
            let path = format!("/{name}/{version}");
            if !seen.insert(path.clone()) {
                anyhow::bail!("MCP_SERVICES でパスが重複: {path}");
            }

            let suffix = env_key_suffix(name, version);
            let cmd_key = format!("MCP_{suffix}_COMMAND");
            let cwd_key = format!("MCP_{suffix}_CWD");
            let command_raw = std::env::var(&cmd_key)
                .map_err(|_| anyhow::anyhow!("{cmd_key} が必要（サービス {name}/{version}）"))?;
            let command = split_command(&command_raw);
            if command.is_empty() {
                anyhow::bail!("{cmd_key} が空");
            }
            let cwd = std::env::var_os(&cwd_key)
                .map(PathBuf::from)
                .unwrap_or_else(|| default_cwd(&self.claude_cwd));

            out.push(ServiceConfig {
                name: name.to_string(),
                version: version.to_string(),
                command,
                cwd,
                path,
            });
        }
        Ok(out)
    }
}

#[cfg(test)]
mod service_config_tests {
    use super::*;

    #[test]
    fn env_key_suffix_uppercases_and_replaces() {
        assert_eq!(env_key_suffix("claude", "v1"), "CLAUDE_V1");
        assert_eq!(env_key_suffix("my-notes", "v2"), "MY_NOTES_V2");
        assert_eq!(env_key_suffix("a", "v10"), "A_V10");
    }

    #[test]
    fn validates_names_and_versions() {
        assert!(valid_service_name("claude"));
        assert!(valid_service_name("a"));
        assert!(valid_service_name("my-notes"));
        assert!(valid_service_name("n0"));
        assert!(!valid_service_name(""));
        assert!(!valid_service_name("-x"));
        assert!(!valid_service_name("x-"));
        assert!(!valid_service_name("My"));
        assert!(!valid_service_name("a/b"));
        assert!(!valid_service_name(".."));
        assert!(valid_version("v1"));
        assert!(valid_version("v2"));
        assert!(valid_version("v10"));
        assert!(!valid_version("1"));
        assert!(!valid_version("v"));
        assert!(!valid_version("version1"));
        assert!(!valid_version("v1a"));
    }

    fn config_from(vars: &[(&str, &str)]) -> Config {
        envy::from_iter(vars.iter().map(|(k, v)| (k.to_string(), v.to_string()))).unwrap()
    }

    #[test]
    fn binds_to_loopback_unless_bind_addr_is_set() {
        let addr = config_from(&[]).listen_addr().unwrap();
        assert_eq!(addr.to_string(), "127.0.0.1:8000");
        let addr = config_from(&[("BIND_ADDR", "0.0.0.0"), ("PORT", "9000")])
            .listen_addr()
            .unwrap();
        assert_eq!(addr.to_string(), "0.0.0.0:9000");
        let addr = config_from(&[("BIND_ADDR", "::1")]).listen_addr().unwrap();
        assert_eq!(addr.to_string(), "[::1]:8000");
        assert!(config_from(&[("BIND_ADDR", "localhost:1")])
            .listen_addr()
            .is_err());
    }

    #[test]
    fn oauth_redirect_allowlist_env_replaces_the_default() {
        let default = config_from(&[]).redirect_allowlist().unwrap();
        assert!(default.allows("https://claude.ai/api/mcp/auth_callback"));
        assert!(!default.allows("https://client.example/cb"));

        let custom = config_from(&[(
            "OAUTH_REDIRECT_ALLOWLIST",
            "https://client.example/cb, https://other.example/app/",
        )])
        .redirect_allowlist()
        .unwrap();
        assert!(custom.allows("https://client.example/cb"));
        assert!(custom.allows("https://other.example/app/x/y"));
        assert!(!custom.allows("https://claude.ai/api/mcp/auth_callback"));

        for bad in ["not a url", "https://x.example/a*", ",,"] {
            assert!(
                config_from(&[("OAUTH_REDIRECT_ALLOWLIST", bad)])
                    .redirect_allowlist()
                    .is_err(),
                "{bad}"
            );
        }
    }
}
