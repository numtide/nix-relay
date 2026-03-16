use futures_util::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_tungstenite::tungstenite;

/// Integration test: start the relay with `cat` as daemon, connect via WS with OIDC token.
#[tokio::test]
async fn test_relay_echo_with_cat_daemon() {
    // Generate RSA keys for test JWTs
    let private_pem = include_str!("../testdata/test_key.pem");
    let public_pem = include_str!("../testdata/test_key.pub.pem");

    let encoding_key = jsonwebtoken::EncodingKey::from_rsa_pem(private_pem.as_bytes()).unwrap();
    let decoding_key = jsonwebtoken::DecodingKey::from_rsa_pem(public_pem.as_bytes()).unwrap();

    let kid = "integration-test-kid";
    let mut keys = HashMap::new();
    keys.insert(kid.to_string(), decoding_key);

    let auth_config = nix_relay::config::AuthConfig {
        issuer: "https://token.actions.githubusercontent.com".to_string(),
        audience: "api://nix-relay".to_string(),
        allowed_org: "testorg".to_string(),
        jwks_cache_ttl_secs: 3600,
        local_key_file: None,
    };

    let auth = nix_relay::auth::AuthService::new_with_oidc_keys(auth_config, keys);

    let daemon_config = nix_relay::config::DaemonConfig {
        nix_daemon_path: "cat".to_string(),
        extra_args: vec![],
        timeout_secs: 10,
        max_connections: 4,
    };

    let state = Arc::new(nix_relay::relay::RelayState {
        auth,
        daemon_config,
        connection_semaphore: Arc::new(Semaphore::new(4)),
    });

    let app = axum::Router::new()
        .route(
            "/relay",
            axum::routing::get(nix_relay::relay::relay_handler),
        )
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // Create a test JWT
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
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
        repository_owner: "testorg".to_string(),
        repository: "testorg/testrepo".to_string(),
    };

    let token = jsonwebtoken::encode(&header, &claims, &encoding_key).unwrap();

    // Connect via WebSocket with auth header
    let url = format!("ws://127.0.0.1:{}/relay", addr.port());
    let request = http::Request::builder()
        .uri(&url)
        .header("Authorization", format!("Bearer {token}"))
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header(
            "Sec-WebSocket-Key",
            tungstenite::handshake::client::generate_key(),
        )
        .header("Host", format!("127.0.0.1:{}", addr.port()))
        .body(())
        .unwrap();

    let (mut ws, _response) = tokio_tungstenite::connect_async(request).await.unwrap();

    // Send data and verify echo (cat echoes stdin to stdout)
    let test_data = b"hello nix-relay!";
    ws.send(tungstenite::Message::Binary(test_data.to_vec().into()))
        .await
        .unwrap();

    let msg = tokio::time::timeout(std::time::Duration::from_secs(5), ws.next())
        .await
        .expect("timeout waiting for echo")
        .expect("stream ended")
        .expect("ws error");

    match msg {
        tungstenite::Message::Binary(data) => {
            assert_eq!(data.as_ref(), test_data, "echoed data should match");
        }
        other => panic!("expected binary message, got: {other:?}"),
    }

    // Send close
    ws.close(None).await.unwrap();
}

/// Test that unauthenticated requests are rejected.
#[tokio::test]
async fn test_relay_rejects_no_auth() {
    let public_pem = include_str!("../testdata/test_key.pub.pem");
    let decoding_key = jsonwebtoken::DecodingKey::from_rsa_pem(public_pem.as_bytes()).unwrap();

    let mut keys = HashMap::new();
    keys.insert("kid".to_string(), decoding_key);

    let auth_config = nix_relay::config::AuthConfig {
        issuer: "https://token.actions.githubusercontent.com".to_string(),
        audience: "api://nix-relay".to_string(),
        allowed_org: "testorg".to_string(),
        jwks_cache_ttl_secs: 3600,
        local_key_file: None,
    };

    let auth = nix_relay::auth::AuthService::new_with_oidc_keys(auth_config, keys);

    let daemon_config = nix_relay::config::DaemonConfig {
        nix_daemon_path: "cat".to_string(),
        extra_args: vec![],
        timeout_secs: 10,
        max_connections: 4,
    };

    let state = Arc::new(nix_relay::relay::RelayState {
        auth,
        daemon_config,
        connection_semaphore: Arc::new(Semaphore::new(4)),
    });

    let app = axum::Router::new()
        .route(
            "/relay",
            axum::routing::get(nix_relay::relay::relay_handler),
        )
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // Try connecting without auth header -- should fail
    let url = format!("ws://127.0.0.1:{}/relay", addr.port());
    let result = tokio_tungstenite::connect_async(&url).await;

    // The server should reject with non-101 status
    assert!(result.is_err(), "expected connection to be rejected");
}

/// Integration test: relay with local Ed25519 JWT auth.
#[tokio::test]
async fn test_relay_echo_with_local_token() {
    use ed25519_dalek::pkcs8::{EncodePrivateKey, EncodePublicKey};
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    // Generate Ed25519 key pair
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    let private_pem = signing_key
        .to_pkcs8_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
        .unwrap();
    let public_pem = verifying_key
        .to_public_key_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
        .unwrap();

    let auth = nix_relay::auth::AuthService::new_local_only(&public_pem).unwrap();

    let daemon_config = nix_relay::config::DaemonConfig {
        nix_daemon_path: "cat".to_string(),
        extra_args: vec![],
        timeout_secs: 10,
        max_connections: 4,
    };

    let state = Arc::new(nix_relay::relay::RelayState {
        auth,
        daemon_config,
        connection_semaphore: Arc::new(Semaphore::new(4)),
    });

    let app = axum::Router::new()
        .route(
            "/relay",
            axum::routing::get(nix_relay::relay::relay_handler),
        )
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // Sign a local JWT
    let encoding_key = jsonwebtoken::EncodingKey::from_ed_pem(private_pem.as_bytes()).unwrap();
    let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA);

    #[derive(serde::Serialize)]
    struct LocalClaims {
        iss: String,
        sub: String,
        iat: u64,
        exp: u64,
    }

    let claims = LocalClaims {
        iss: "nix-relay".to_string(),
        sub: "bench-test".to_string(),
        iat: jsonwebtoken::get_current_timestamp(),
        exp: jsonwebtoken::get_current_timestamp() + 3600,
    };

    let token = jsonwebtoken::encode(&header, &claims, &encoding_key).unwrap();

    // Connect via WebSocket with auth header
    let url = format!("ws://127.0.0.1:{}/relay", addr.port());
    let request = http::Request::builder()
        .uri(&url)
        .header("Authorization", format!("Bearer {token}"))
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header(
            "Sec-WebSocket-Key",
            tungstenite::handshake::client::generate_key(),
        )
        .header("Host", format!("127.0.0.1:{}", addr.port()))
        .body(())
        .unwrap();

    let (mut ws, _response) = tokio_tungstenite::connect_async(request).await.unwrap();

    // Send data and verify echo
    let test_data = b"hello local jwt!";
    ws.send(tungstenite::Message::Binary(test_data.to_vec().into()))
        .await
        .unwrap();

    let msg = tokio::time::timeout(std::time::Duration::from_secs(5), ws.next())
        .await
        .expect("timeout waiting for echo")
        .expect("stream ended")
        .expect("ws error");

    match msg {
        tungstenite::Message::Binary(data) => {
            assert_eq!(data.as_ref(), test_data, "echoed data should match");
        }
        other => panic!("expected binary message, got: {other:?}"),
    }

    ws.close(None).await.unwrap();
}
