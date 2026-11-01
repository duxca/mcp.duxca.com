//! 環境変数からの設定。

use crate::auth::RedirectAllowlist;
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};

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

    /// 添付の総量上限（バイト）。メモリに持つので小さめ。
    #[serde(default = "default_relay_max_total_storage_bytes")]
    pub relay_max_total_storage_bytes: u64,
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

fn default_relay_max_total_storage_bytes() -> u64 {
    crate::relay::DEFAULT_MAX_TOTAL_STORAGE_BYTES
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
}

#[cfg(test)]
mod service_config_tests {
    use super::*;

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
