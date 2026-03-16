use serde::Deserialize;
use std::path::PathBuf;

use crate::error::Error;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub daemon: DaemonConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_listen")]
    pub listen: String,
    #[serde(default = "default_shutdown_grace_secs")]
    pub shutdown_grace_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthConfig {
    #[serde(default = "default_issuer")]
    pub issuer: String,
    #[serde(default = "default_audience")]
    pub audience: String,
    #[serde(default)]
    pub allowed_org: String,
    #[serde(default = "default_jwks_cache_ttl_secs")]
    pub jwks_cache_ttl_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DaemonConfig {
    #[serde(default = "default_nix_daemon_path")]
    pub nix_daemon_path: String,
    #[serde(default = "default_extra_args")]
    pub extra_args: Vec<String>,
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
}

fn default_listen() -> String {
    "0.0.0.0:8080".to_string()
}
fn default_shutdown_grace_secs() -> u64 {
    30
}
fn default_issuer() -> String {
    "https://token.actions.githubusercontent.com".to_string()
}
fn default_audience() -> String {
    "api://nix-relay".to_string()
}
fn default_jwks_cache_ttl_secs() -> u64 {
    3600
}
fn default_nix_daemon_path() -> String {
    "nix-daemon".to_string()
}
fn default_extra_args() -> Vec<String> {
    vec!["--stdio".to_string()]
}
fn default_timeout_secs() -> u64 {
    3600
}
fn default_max_connections() -> u32 {
    32
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            shutdown_grace_secs: default_shutdown_grace_secs(),
        }
    }
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            issuer: default_issuer(),
            audience: default_audience(),
            allowed_org: String::new(),
            jwks_cache_ttl_secs: default_jwks_cache_ttl_secs(),
        }
    }
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            nix_daemon_path: default_nix_daemon_path(),
            extra_args: default_extra_args(),
            timeout_secs: default_timeout_secs(),
            max_connections: default_max_connections(),
        }
    }
}

impl Config {
    pub fn load(path: Option<PathBuf>) -> Result<Self, Error> {
        let mut config = if let Some(path) = path {
            let content = std::fs::read_to_string(&path)
                .map_err(|e| Error::Config(format!("reading {}: {}", path.display(), e)))?;
            toml::from_str(&content)
                .map_err(|e| Error::Config(format!("parsing {}: {}", path.display(), e)))?
        } else {
            Config {
                server: ServerConfig::default(),
                auth: AuthConfig::default(),
                daemon: DaemonConfig::default(),
            }
        };

        // Environment variable overrides
        if let Ok(v) = std::env::var("NIX_RELAY_LISTEN") {
            config.server.listen = v;
        }
        if let Ok(v) = std::env::var("NIX_RELAY_SHUTDOWN_GRACE_SECS") {
            config.server.shutdown_grace_secs = v
                .parse()
                .map_err(|e| Error::Config(format!("NIX_RELAY_SHUTDOWN_GRACE_SECS: {e}")))?;
        }
        if let Ok(v) = std::env::var("NIX_RELAY_ISSUER") {
            config.auth.issuer = v;
        }
        if let Ok(v) = std::env::var("NIX_RELAY_AUDIENCE") {
            config.auth.audience = v;
        }
        if let Ok(v) = std::env::var("NIX_RELAY_ALLOWED_ORG") {
            config.auth.allowed_org = v;
        }
        if let Ok(v) = std::env::var("NIX_RELAY_JWKS_CACHE_TTL_SECS") {
            config.auth.jwks_cache_ttl_secs = v
                .parse()
                .map_err(|e| Error::Config(format!("NIX_RELAY_JWKS_CACHE_TTL_SECS: {e}")))?;
        }
        if let Ok(v) = std::env::var("NIX_RELAY_DAEMON_PATH") {
            config.daemon.nix_daemon_path = v;
        }
        if let Ok(v) = std::env::var("NIX_RELAY_TIMEOUT_SECS") {
            config.daemon.timeout_secs = v
                .parse()
                .map_err(|e| Error::Config(format!("NIX_RELAY_TIMEOUT_SECS: {e}")))?;
        }
        if let Ok(v) = std::env::var("NIX_RELAY_MAX_CONNECTIONS") {
            config.daemon.max_connections = v
                .parse()
                .map_err(|e| Error::Config(format!("NIX_RELAY_MAX_CONNECTIONS: {e}")))?;
        }

        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_defaults() {
        let config = Config::load(None).unwrap();
        assert_eq!(config.server.listen, "0.0.0.0:8080");
        assert_eq!(
            config.auth.issuer,
            "https://token.actions.githubusercontent.com"
        );
        assert_eq!(config.daemon.max_connections, 32);
    }

    #[test]
    fn test_parse_toml() {
        let dir = std::env::temp_dir().join("nix-relay-test-config");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.toml");
        std::fs::write(
            &path,
            r#"
[server]
listen = "127.0.0.1:9090"

[auth]
allowed_org = "testorg"

[daemon]
max_connections = 8
"#,
        )
        .unwrap();

        let config = Config::load(Some(path)).unwrap();
        assert_eq!(config.server.listen, "127.0.0.1:9090");
        assert_eq!(config.auth.allowed_org, "testorg");
        assert_eq!(config.daemon.max_connections, 8);
        // Defaults still apply for unset values
        assert_eq!(config.daemon.timeout_secs, 3600);
    }
}
