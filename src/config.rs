//! 環境変数からの設定。

use std::collections::HashSet;

#[derive(Debug, Clone, serde::Deserialize)]
pub struct Config {
    /// 公開オリジン（スキーム+ホスト。末尾スラッシュなし）。例: https://mcp.duxca.com
    #[serde(default = "default_public_url")]
    pub public_url: String,

    #[serde(default = "default_port")]
    pub port: u16,

    #[serde(default)]
    pub github_client_id: String,

    #[serde(default)]
    pub github_client_secret: String,

    /// カンマ区切りの GitHub 数値 id。login は改名で再利用されうるので使わない。
    #[serde(default = "default_allowed_ids")]
    pub allowed_github_ids: String,

    /// `claude mcp serve` など。シェル風に空白分割する。
    #[serde(default = "default_claude_command")]
    pub claude_mcp_command: String,

    #[serde(default)]
    pub claude_cwd: Option<String>,
}

fn default_public_url() -> String {
    "http://127.0.0.1:8000".into()
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

    pub fn claude_command_argv(&self) -> Vec<String> {
        self.claude_mcp_command
            .split_whitespace()
            .map(str::to_string)
            .collect()
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

    pub fn github_configured(&self) -> bool {
        !self.github_client_id.is_empty() && !self.github_client_secret.is_empty()
    }
}
