use axum::routing::get;
use axum::Router;
use clap::Parser;
use nix_relay::auth::AuthService;
use nix_relay::config::Config;
use nix_relay::relay::{relay_handler, RelayState};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::signal;
use tokio::sync::Semaphore;
use tracing::{error, info};

#[derive(Parser)]
#[command(about = "OIDC-authenticated Nix remote build relay")]
enum Cli {
    /// Start the relay server
    Serve {
        /// Path to config file
        config: Option<PathBuf>,
    },
    /// Key management
    Key {
        #[command(subcommand)]
        cmd: KeyCmd,
    },
    /// Token management
    Token {
        #[command(subcommand)]
        cmd: TokenCmd,
    },
}

#[derive(clap::Subcommand)]
enum KeyCmd {
    /// Generate a new Ed25519 key pair
    Generate {
        /// Output directory for private.pem and public.pem
        #[arg(long, default_value = "/var/lib/nix-relay")]
        output: PathBuf,
    },
}

#[derive(clap::Subcommand)]
enum TokenCmd {
    /// Generate a signed JWT token
    Generate {
        /// Path to Ed25519 private key (PEM)
        #[arg(long)]
        key_file: PathBuf,
        /// Token expiration duration (e.g. 1h, 30m, 7d)
        #[arg(long, default_value = "1h")]
        exp: String,
        /// Client label embedded in the token
        #[arg(long, default_value = "local")]
        label: String,
    },
}

/// Parse a duration string like "1h", "30m", "7d", "3600s" into seconds.
fn parse_duration(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty duration".to_string());
    }
    let (num_str, multiplier) = if let Some(n) = s.strip_suffix('d') {
        (n, 86400u64)
    } else if let Some(n) = s.strip_suffix('h') {
        (n, 3600u64)
    } else if let Some(n) = s.strip_suffix('m') {
        (n, 60u64)
    } else if let Some(n) = s.strip_suffix('s') {
        (n, 1u64)
    } else {
        // Assume seconds if no suffix
        (s, 1u64)
    };
    let num: u64 = num_str
        .parse()
        .map_err(|e| format!("invalid duration '{s}': {e}"))?;
    Ok(num * multiplier)
}

fn cmd_key_generate(output: PathBuf) {
    use ed25519_dalek::pkcs8::{EncodePrivateKey, EncodePublicKey};
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    std::fs::create_dir_all(&output).unwrap_or_else(|e| {
        eprintln!("error: cannot create directory {}: {e}", output.display());
        std::process::exit(1);
    });

    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    let private_pem = signing_key
        .to_pkcs8_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
        .unwrap_or_else(|e| {
            eprintln!("error: failed to encode private key: {e}");
            std::process::exit(1);
        });
    let public_pem = verifying_key
        .to_public_key_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
        .unwrap_or_else(|e| {
            eprintln!("error: failed to encode public key: {e}");
            std::process::exit(1);
        });

    let private_path = output.join("private.pem");
    let public_path = output.join("public.pem");

    std::fs::write(&private_path, private_pem.as_bytes()).unwrap_or_else(|e| {
        eprintln!("error: writing {}: {e}", private_path.display());
        std::process::exit(1);
    });
    std::fs::write(&public_path, public_pem.as_bytes()).unwrap_or_else(|e| {
        eprintln!("error: writing {}: {e}", public_path.display());
        std::process::exit(1);
    });

    // Set private key permissions to 0600 on unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&private_path, std::fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|e| {
                eprintln!(
                    "warning: failed to set permissions on {}: {e}",
                    private_path.display()
                );
            });
    }

    eprintln!("private key: {}", private_path.display());
    eprintln!("public key:  {}", public_path.display());
}

fn cmd_token_generate(key_file: PathBuf, exp: String, label: String) {
    let private_pem = std::fs::read_to_string(&key_file).unwrap_or_else(|e| {
        eprintln!("error: reading {}: {e}", key_file.display());
        std::process::exit(1);
    });

    let duration_secs = parse_duration(&exp).unwrap_or_else(|e| {
        eprintln!("error: {e}");
        std::process::exit(1);
    });

    let encoding_key = jsonwebtoken::EncodingKey::from_ed_pem(private_pem.as_bytes())
        .unwrap_or_else(|e| {
            eprintln!("error: invalid Ed25519 private key: {e}");
            std::process::exit(1);
        });

    let now = jsonwebtoken::get_current_timestamp();

    #[derive(serde::Serialize)]
    struct Claims {
        iss: String,
        sub: String,
        iat: u64,
        exp: u64,
    }

    let claims = Claims {
        iss: "nix-relay".to_string(),
        sub: label,
        iat: now,
        exp: now + duration_secs,
    };

    let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA);
    let token = jsonwebtoken::encode(&header, &claims, &encoding_key).unwrap_or_else(|e| {
        eprintln!("error: failed to sign token: {e}");
        std::process::exit(1);
    });

    println!("{token}");
}

#[tokio::main]
async fn main() {
    // For backwards compat: if no subcommand given and first arg looks like a file path
    // or NIX_RELAY_CONFIG is set, treat as `serve`.
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            // If parsing fails, check if we should fall back to serve mode
            let args: Vec<String> = std::env::args().collect();
            if args.len() <= 2 && e.kind() == clap::error::ErrorKind::InvalidSubcommand {
                // Likely a bare config path -- treat as serve
                Cli::Serve {
                    config: args.get(1).map(PathBuf::from),
                }
            } else {
                e.exit();
            }
        }
    };

    match cli {
        Cli::Serve { config } => cmd_serve(config).await,
        Cli::Key { cmd } => match cmd {
            KeyCmd::Generate { output } => cmd_key_generate(output),
        },
        Cli::Token { cmd } => match cmd {
            TokenCmd::Generate {
                key_file,
                exp,
                label,
            } => cmd_token_generate(key_file, exp, label),
        },
    }
}

async fn cmd_serve(config_path: Option<PathBuf>) {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "nix_relay=info".parse().unwrap()),
        )
        .init();

    let config_path =
        config_path.or_else(|| std::env::var("NIX_RELAY_CONFIG").ok().map(PathBuf::from));

    let config = match Config::load(config_path) {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "failed to load config");
            std::process::exit(1);
        }
    };

    if !config.auth.has_any_backend() {
        error!("no auth backend configured: set auth.allowed_org (OIDC) and/or auth.local_key_file (local JWT)");
        std::process::exit(1);
    }

    // Build OIDC config if allowed_org is set
    let oidc_config = if config.auth.has_oidc() {
        Some(config.auth.clone())
    } else {
        None
    };

    // Read local key PEM if configured
    let local_key_pem = match &config.auth.local_key_file {
        Some(path) => {
            let pem = match std::fs::read_to_string(path) {
                Ok(p) => p,
                Err(e) => {
                    error!(path = %path, error = %e, "failed to read local key file");
                    std::process::exit(1);
                }
            };
            Some(pem)
        }
        None => None,
    };

    info!(
        listen = %config.server.listen,
        oidc = config.auth.has_oidc(),
        local_jwt = config.auth.has_local_key(),
        "starting nix-relay"
    );

    let auth = match AuthService::new(oidc_config, local_key_pem).await {
        Ok(a) => a,
        Err(e) => {
            error!(error = %e, "failed to initialize auth");
            std::process::exit(1);
        }
    };

    let state = Arc::new(RelayState {
        auth,
        daemon_config: config.daemon.clone(),
        connection_semaphore: Arc::new(Semaphore::new(config.daemon.max_connections as usize)),
    });

    let app = Router::new()
        .route("/relay", get(relay_handler))
        .with_state(state);

    let listener = match TcpListener::bind(&config.server.listen).await {
        Ok(l) => l,
        Err(e) => {
            error!(addr = %config.server.listen, error = %e, "failed to bind");
            std::process::exit(1);
        }
    };

    info!(addr = %config.server.listen, "listening");

    let grace = std::time::Duration::from_secs(config.server.shutdown_grace_secs);
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();

    info!(grace_secs = grace.as_secs(), "shutting down gracefully");
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => info!("received Ctrl+C"),
        _ = terminate => info!("received SIGTERM"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_duration() {
        assert_eq!(parse_duration("1h").unwrap(), 3600);
        assert_eq!(parse_duration("30m").unwrap(), 1800);
        assert_eq!(parse_duration("7d").unwrap(), 604800);
        assert_eq!(parse_duration("3600s").unwrap(), 3600);
        assert_eq!(parse_duration("3600").unwrap(), 3600);
        assert!(parse_duration("").is_err());
        assert!(parse_duration("abc").is_err());
    }
}
