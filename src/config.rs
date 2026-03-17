use figment2::{
    Figment,
    providers::{Env, Format, Serialized, Toml},
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::error::Error;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub daemon: DaemonConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    pub listen: String,
    pub shutdown_grace_secs: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthConfig {
    pub issuer: String,
    pub audience: String,
    pub allowed_org: String,
    pub jwks_cache_ttl_secs: u64,
    /// Path to Ed25519 public key PEM for local JWT auth
    pub local_key_file: Option<String>,
}

impl AuthConfig {
    pub fn has_oidc(&self) -> bool {
        !self.allowed_org.is_empty()
    }

    pub fn has_local_key(&self) -> bool {
        self.local_key_file.is_some()
    }

    pub fn has_any_backend(&self) -> bool {
        self.has_oidc() || self.has_local_key()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DaemonConfig {
    pub nix_daemon_path: String,
    pub extra_args: Vec<String>,
    pub timeout_secs: u64,
    pub max_connections: u32,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:8080".to_string(),
            shutdown_grace_secs: 30,
        }
    }
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            issuer: "https://token.actions.githubusercontent.com".to_string(),
            audience: "api://nix-relay".to_string(),
            allowed_org: String::new(),
            jwks_cache_ttl_secs: 3600,
            local_key_file: None,
        }
    }
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            nix_daemon_path: "nix-daemon".to_string(),
            extra_args: vec!["--stdio".to_string()],
            timeout_secs: 3600,
            max_connections: 32,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: Default::default(),
            auth: Default::default(),
            daemon: Default::default(),
        }
    }
}

impl Config {
    pub fn load(path: Option<PathBuf>) -> Result<Self, Error> {
        let mut figment = Figment::from(Serialized::from(Config::default(), "default"));
        if let Some(path) = path {
            figment = figment.merge(Toml::file(path));
        }
        figment = figment.merge(Env::prefixed("NIX_RELAY_"));

        let config: Config = figment
            .extract()
            .map_err(|e| Error::Config(format!("building config: {}", e)))?;

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
        assert!(config.auth.local_key_file.is_none());
    }

    #[test]
    fn test_parse_toml_with_local_key() {
        let dir = std::env::temp_dir().join("nix-relay-test-config-local");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.toml");
        std::fs::write(
            &path,
            r#"
[auth]
local_key_file = "/var/lib/nix-relay/public.pem"
"#,
        )
        .unwrap();

        let config = Config::load(Some(path)).unwrap();
        assert_eq!(
            config.auth.local_key_file.as_deref(),
            Some("/var/lib/nix-relay/public.pem")
        );
        assert!(config.auth.has_local_key());
        assert!(!config.auth.has_oidc());
        assert!(config.auth.has_any_backend());
    }
}
