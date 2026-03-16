use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, TokenData, Validation};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::config::AuthConfig;
use crate::error::Error;

/// Backend-agnostic authentication result.
#[derive(Debug, Clone)]
pub struct AuthInfo {
    pub client_identity: String,
}

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

/// Validates locally-issued Ed25519 JWTs.
pub struct LocalValidator {
    decoding_key: DecodingKey,
}

#[derive(Debug, Deserialize)]
struct LocalClaims {
    sub: Option<String>,
}

impl LocalValidator {
    pub fn new(public_key_pem: &str) -> Result<Self, Error> {
        let key = DecodingKey::from_ed_pem(public_key_pem.as_bytes())
            .map_err(|e| Error::Config(format!("invalid Ed25519 public key: {e}")))?;
        Ok(Self { decoding_key: key })
    }

    pub fn validate_token(&self, token: &str) -> Result<AuthInfo, Error> {
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&["nix-relay"]);
        validation.validate_aud = false;
        let data = decode::<LocalClaims>(token, &self.decoding_key, &validation)?;
        Ok(AuthInfo {
            client_identity: data.claims.sub.unwrap_or_else(|| "local".to_string()),
        })
    }
}

/// Composes OIDC and local JWT auth backends.
pub struct AuthService {
    oidc: Option<AuthValidator>,
    local: Option<LocalValidator>,
}

impl AuthService {
    pub async fn new(
        oidc_config: Option<AuthConfig>,
        local_key_pem: Option<String>,
    ) -> Result<Self, Error> {
        let oidc = match oidc_config {
            Some(cfg) => Some(AuthValidator::new(cfg).await?),
            None => None,
        };
        let local = match local_key_pem {
            Some(pem) => Some(LocalValidator::new(&pem)?),
            None => None,
        };
        Ok(Self { oidc, local })
    }

    /// Create an AuthService with pre-loaded OIDC keys (for testing).
    pub fn new_with_oidc_keys(config: AuthConfig, keys: HashMap<String, DecodingKey>) -> Self {
        Self {
            oidc: Some(AuthValidator::new_with_keys(config, keys)),
            local: None,
        }
    }

    /// Create an AuthService with only local JWT validation (for testing).
    pub fn new_local_only(public_key_pem: &str) -> Result<Self, Error> {
        Ok(Self {
            oidc: None,
            local: Some(LocalValidator::new(public_key_pem)?),
        })
    }

    pub async fn validate_token(&self, token: &str) -> Result<AuthInfo, Error> {
        // Try local first (cheap, no I/O)
        if let Some(ref lv) = self.local {
            match lv.validate_token(token) {
                Ok(info) => return Ok(info),
                Err(_) => {} // fall through to OIDC
            }
        }
        // Try OIDC
        if let Some(ref oidc) = self.oidc {
            let data = oidc.validate_token(token).await?;
            return Ok(AuthInfo {
                client_identity: data
                    .claims
                    .repository
                    .unwrap_or_else(|| "unknown".to_string()),
            });
        }
        Err(Error::Unauthorized(
            "no auth backend accepted the token".into(),
        ))
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
            local_key_file: None,
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
            local_key_file: None,
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

    fn generate_ed25519_keys() -> (ed25519_dalek::SigningKey, ed25519_dalek::VerifyingKey) {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        (signing_key, verifying_key)
    }

    fn ed25519_pem_pair() -> (String, String) {
        use ed25519_dalek::pkcs8::{EncodePrivateKey, EncodePublicKey};
        let (signing_key, verifying_key) = generate_ed25519_keys();
        let private_pem = signing_key
            .to_pkcs8_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
            .unwrap();
        let public_pem = verifying_key
            .to_public_key_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
            .unwrap();
        (private_pem.to_string(), public_pem)
    }

    #[test]
    fn test_local_validator_valid_token() {
        let (private_pem, public_pem) = ed25519_pem_pair();
        let validator = LocalValidator::new(&public_pem).unwrap();

        let encoding_key = EncodingKey::from_ed_pem(private_pem.as_bytes()).unwrap();
        let header = Header::new(Algorithm::EdDSA);

        #[derive(serde::Serialize)]
        struct Claims {
            iss: String,
            sub: String,
            exp: u64,
            iat: u64,
        }

        let claims = Claims {
            iss: "nix-relay".to_string(),
            sub: "bench".to_string(),
            exp: jsonwebtoken::get_current_timestamp() + 3600,
            iat: jsonwebtoken::get_current_timestamp(),
        };

        let token = encode(&header, &claims, &encoding_key).unwrap();
        let info = validator.validate_token(&token).unwrap();
        assert_eq!(info.client_identity, "bench");
    }

    #[test]
    fn test_local_validator_wrong_issuer() {
        let (private_pem, public_pem) = ed25519_pem_pair();
        let validator = LocalValidator::new(&public_pem).unwrap();

        let encoding_key = EncodingKey::from_ed_pem(private_pem.as_bytes()).unwrap();
        let header = Header::new(Algorithm::EdDSA);

        #[derive(serde::Serialize)]
        struct Claims {
            iss: String,
            sub: String,
            exp: u64,
        }

        let claims = Claims {
            iss: "wrong-issuer".to_string(),
            sub: "test".to_string(),
            exp: jsonwebtoken::get_current_timestamp() + 3600,
        };

        let token = encode(&header, &claims, &encoding_key).unwrap();
        assert!(validator.validate_token(&token).is_err());
    }

    #[test]
    fn test_local_validator_expired_token() {
        let (private_pem, public_pem) = ed25519_pem_pair();
        let validator = LocalValidator::new(&public_pem).unwrap();

        let encoding_key = EncodingKey::from_ed_pem(private_pem.as_bytes()).unwrap();
        let header = Header::new(Algorithm::EdDSA);

        #[derive(serde::Serialize)]
        struct Claims {
            iss: String,
            sub: String,
            exp: u64,
        }

        let claims = Claims {
            iss: "nix-relay".to_string(),
            sub: "test".to_string(),
            exp: 1, // long expired
        };

        let token = encode(&header, &claims, &encoding_key).unwrap();
        assert!(validator.validate_token(&token).is_err());
    }

    #[test]
    fn test_local_validator_wrong_key() {
        let (private_pem, _) = ed25519_pem_pair();
        let (_, other_public_pem) = ed25519_pem_pair();
        let validator = LocalValidator::new(&other_public_pem).unwrap();

        let encoding_key = EncodingKey::from_ed_pem(private_pem.as_bytes()).unwrap();
        let header = Header::new(Algorithm::EdDSA);

        #[derive(serde::Serialize)]
        struct Claims {
            iss: String,
            sub: String,
            exp: u64,
        }

        let claims = Claims {
            iss: "nix-relay".to_string(),
            sub: "test".to_string(),
            exp: jsonwebtoken::get_current_timestamp() + 3600,
        };

        let token = encode(&header, &claims, &encoding_key).unwrap();
        assert!(validator.validate_token(&token).is_err());
    }
}
