use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, TokenData, Validation};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::config::AuthConfig;
use crate::error::Error;

#[derive(Debug, Deserialize)]
struct OidcDiscovery {
    jwks_uri: String,
}

#[derive(Debug, Clone, Deserialize)]
struct JwkSet {
    keys: Vec<Jwk>,
}

#[derive(Debug, Clone, Deserialize)]
struct Jwk {
    kid: String,
    kty: String,
    #[serde(default)]
    n: String,
    #[serde(default)]
    e: String,
}

#[derive(Debug, Deserialize)]
pub struct GitHubClaims {
    pub repository_owner: Option<String>,
    pub repository: Option<String>,
}

struct JwksCache {
    keys: HashMap<String, DecodingKey>,
    last_refresh: Instant,
}

pub struct AuthValidator {
    config: AuthConfig,
    http: reqwest::Client,
    cache: Arc<RwLock<Option<JwksCache>>>,
}

impl AuthValidator {
    pub async fn new(config: AuthConfig) -> Result<Self, Error> {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .connect_timeout(std::time::Duration::from_secs(5))
            .build()
            .expect("reqwest client builder with static config cannot fail");
        let validator = Self {
            config,
            http,
            cache: Arc::new(RwLock::new(None)),
        };
        // Pre-fetch JWKS on startup
        validator.refresh_jwks().await?;
        Ok(validator)
    }

    /// Create an AuthValidator without fetching JWKS (for testing).
    pub fn new_with_keys(config: AuthConfig, keys: HashMap<String, DecodingKey>) -> Self {
        Self {
            config,
            http: reqwest::Client::new(),
            cache: Arc::new(RwLock::new(Some(JwksCache {
                keys,
                last_refresh: Instant::now() - std::time::Duration::from_secs(120),
            }))),
        }
    }

    async fn refresh_jwks(&self) -> Result<(), Error> {
        let discovery_url = format!(
            "{}/.well-known/openid-configuration",
            self.config.issuer.trim_end_matches('/')
        );
        debug!(url = %discovery_url, "fetching OIDC discovery document");

        let discovery: OidcDiscovery = self
            .http
            .get(&discovery_url)
            .send()
            .await?
            .error_for_status()
            .map_err(|e| Error::Jwks(format!("discovery fetch failed: {e}")))?
            .json()
            .await?;

        debug!(uri = %discovery.jwks_uri, "fetching JWKS");

        let jwks: JwkSet = self
            .http
            .get(&discovery.jwks_uri)
            .send()
            .await?
            .error_for_status()
            .map_err(|e| Error::Jwks(format!("JWKS fetch failed: {e}")))?
            .json()
            .await?;

        let mut keys = HashMap::new();
        for jwk in &jwks.keys {
            if jwk.kty == "RSA" {
                match DecodingKey::from_rsa_components(&jwk.n, &jwk.e) {
                    Ok(key) => {
                        keys.insert(jwk.kid.clone(), key);
                    }
                    Err(e) => {
                        warn!(kid = %jwk.kid, error = %e, "skipping invalid JWK");
                    }
                }
            }
        }

        info!(count = keys.len(), "cached JWKS keys");

        let mut cache = self.cache.write().await;
        *cache = Some(JwksCache {
            keys,
            last_refresh: Instant::now(),
        });

        Ok(())
    }

    async fn get_key(&self, kid: &str) -> Result<DecodingKey, Error> {
        // Try from cache first
        {
            let cache = self.cache.read().await;
            if let Some(c) = cache.as_ref() {
                if let Some(key) = c.keys.get(kid) {
                    return Ok(key.clone());
                }
            }
        }

        // Unknown kid -- force refresh if not refreshed in last 60s
        {
            let cache = self.cache.read().await;
            if let Some(c) = cache.as_ref() {
                if c.last_refresh.elapsed().as_secs() < 60 {
                    return Err(Error::Jwks(format!("unknown kid: {kid}")));
                }
            }
        }

        info!(kid, "unknown kid, refreshing JWKS");
        self.refresh_jwks().await?;

        let cache = self.cache.read().await;
        cache
            .as_ref()
            .and_then(|c| c.keys.get(kid).cloned())
            .ok_or_else(|| Error::Jwks(format!("unknown kid after refresh: {kid}")))
    }

    pub async fn validate_token(&self, token: &str) -> Result<TokenData<GitHubClaims>, Error> {
        let header = decode_header(token)?;
        let kid = header
            .kid
            .as_deref()
            .ok_or_else(|| Error::Jwks("token missing kid header".to_string()))?;

        let key = self.get_key(kid).await?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&self.config.issuer]);
        validation.set_audience(&[&self.config.audience]);

        let token_data = decode::<GitHubClaims>(token, &key, &validation)?;

        // Check org
        if !self.config.allowed_org.is_empty() {
            let owner = token_data.claims.repository_owner.as_deref().unwrap_or("");
            if !owner.eq_ignore_ascii_case(&self.config.allowed_org) {
                return Err(Error::Unauthorized(format!(
                    "repository_owner '{owner}' not in allowed org '{}'",
                    self.config.allowed_org
                )));
            }
        }

        Ok(token_data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};

    fn generate_rsa_keys() -> (EncodingKey, DecodingKey) {
        // Generate a test RSA key pair using the rsa crate is complex,
        // so we use a pre-generated PEM for tests.
        let rsa = rsa_key_for_tests();
        let encoding = EncodingKey::from_rsa_pem(rsa.0.as_bytes()).unwrap();
        let decoding = DecodingKey::from_rsa_pem(rsa.1.as_bytes()).unwrap();
        (encoding, decoding)
    }

    // Minimal 2048-bit RSA test key pair
    fn rsa_key_for_tests() -> (&'static str, &'static str) {
        (
            include_str!("../testdata/test_key.pem"),
            include_str!("../testdata/test_key.pub.pem"),
        )
    }

    #[test]
    fn test_validate_valid_token() {
        let (encoding_key, decoding_key) = generate_rsa_keys();

        let config = AuthConfig {
            issuer: "https://token.actions.githubusercontent.com".to_string(),
            audience: "api://nix-relay".to_string(),
            allowed_org: "myorg".to_string(),
            jwks_cache_ttl_secs: 3600,
        };

        let kid = "test-kid-1";
        let mut keys = HashMap::new();
        keys.insert(kid.to_string(), decoding_key);

        let validator = AuthValidator::new_with_keys(config, keys);

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.to_string());

        #[derive(serde::Serialize)]
        struct TestClaims {
            iss: String,
            aud: String,
            exp: u64,
            repository_owner: String,
            repository: String,
        }

        let claims = TestClaims {
            iss: "https://token.actions.githubusercontent.com".to_string(),
            aud: "api://nix-relay".to_string(),
            exp: jsonwebtoken::get_current_timestamp() + 3600,
            repository_owner: "myorg".to_string(),
            repository: "myorg/myrepo".to_string(),
        };

        let token = encode(&header, &claims, &encoding_key).unwrap();

        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(validator.validate_token(&token));
        assert!(result.is_ok());
        let data = result.unwrap();
        assert_eq!(data.claims.repository_owner.as_deref(), Some("myorg"));
    }

    #[test]
    fn test_validate_wrong_org() {
        let (encoding_key, decoding_key) = generate_rsa_keys();

        let config = AuthConfig {
            issuer: "https://token.actions.githubusercontent.com".to_string(),
            audience: "api://nix-relay".to_string(),
            allowed_org: "myorg".to_string(),
            jwks_cache_ttl_secs: 3600,
        };

        let kid = "test-kid-1";
        let mut keys = HashMap::new();
        keys.insert(kid.to_string(), decoding_key);

        let validator = AuthValidator::new_with_keys(config, keys);

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.to_string());

        #[derive(serde::Serialize)]
        struct TestClaims {
            iss: String,
            aud: String,
            exp: u64,
            repository_owner: String,
        }

        let claims = TestClaims {
            iss: "https://token.actions.githubusercontent.com".to_string(),
            aud: "api://nix-relay".to_string(),
            exp: jsonwebtoken::get_current_timestamp() + 3600,
            repository_owner: "evilorg".to_string(),
        };

        let token = encode(&header, &claims, &encoding_key).unwrap();

        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(validator.validate_token(&token));
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("evilorg"), "error: {err}");
    }
}
