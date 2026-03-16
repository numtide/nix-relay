use axum::extract::ws::{Message, WebSocket};
use axum::extract::{State, WebSocketUpgrade};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use futures_util::{SinkExt, StreamExt};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};

use crate::auth::AuthService;
use crate::config::DaemonConfig;
use crate::error::Error;

pub struct RelayState {
    pub auth: AuthService,
    pub daemon_config: DaemonConfig,
    pub connection_semaphore: Arc<Semaphore>,
}

pub async fn relay_handler(
    State(state): State<Arc<RelayState>>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Result<impl IntoResponse, Error> {
    // Extract and validate JWT before upgrading
    let auth_header = headers
        .get("authorization")
        .ok_or(Error::MissingAuth)?
        .to_str()
        .map_err(|_| Error::InvalidAuthFormat)?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or(Error::InvalidAuthFormat)?;

    let auth_info = state.auth.validate_token(token).await?;
    let client = auth_info.client_identity;
    info!(client = %client, "authenticated client");

    // Acquire connection permit
    let permit = state
        .connection_semaphore
        .clone()
        .try_acquire_owned()
        .map_err(|_| Error::TooManyConnections)?;

    let daemon_config = state.daemon_config.clone();
    let timeout_secs = daemon_config.timeout_secs;

    Ok(ws
        .protocols(["binary"])
        .on_upgrade(move |socket| async move {
            let _permit = permit; // Hold permit for duration
            if let Err(e) = handle_connection(socket, daemon_config, timeout_secs, &client).await {
                error!(client = %client, error = %e, "relay session ended with error");
            }
        }))
}

async fn handle_connection(
    socket: WebSocket,
    daemon_config: DaemonConfig,
    timeout_secs: u64,
    client: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut cmd = Command::new(&daemon_config.nix_daemon_path);
    for arg in &daemon_config.extra_args {
        cmd.arg(arg);
    }
    cmd.stdin(std::process::Stdio::piped());
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    let mut child = cmd.spawn().map_err(Error::DaemonSpawn)?;
    let mut daemon_stdin = child.stdin.take().expect("stdin piped");
    let mut daemon_stdout = child.stdout.take().expect("stdout piped");
    let mut daemon_stderr = child.stderr.take().expect("stderr piped");

    info!(client = %client, pid = child.id().unwrap_or(0), "spawned daemon");

    let (mut ws_sink, mut ws_stream) = socket.split();

    let timeout = tokio::time::Duration::from_secs(timeout_secs);

    // Spawn stderr logger
    let client_clone = client.to_string();
    let stderr_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            match daemon_stderr.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    let text = String::from_utf8_lossy(&buf[..n]);
                    debug!(client = %client_clone, stderr = %text, "daemon stderr");
                }
                Err(e) => {
                    warn!(error = %e, "daemon stderr read error");
                    break;
                }
            }
        }
    });

    // Bidirectional relay with timeout
    let result = tokio::time::timeout(timeout, async {
        let mut stdout_buf = vec![0u8; 64 * 1024];
        loop {
            tokio::select! {
                // WS -> daemon stdin
                msg = ws_stream.next() => {
                    match msg {
                        Some(Ok(Message::Binary(data))) => {
                            if let Err(e) = daemon_stdin.write_all(&data).await {
                                debug!(error = %e, "daemon stdin write error");
                                break;
                            }
                        }
                        Some(Ok(Message::Close(_))) | None => {
                            debug!("WebSocket closed by client");
                            break;
                        }
                        Some(Err(e)) => {
                            debug!(error = %e, "WebSocket receive error");
                            break;
                        }
                        _ => {
                            // Ignore non-binary frames (ping/pong handled by axum)
                        }
                    }
                }
                // daemon stdout -> WS
                n = daemon_stdout.read(&mut stdout_buf) => {
                    match n {
                        Ok(0) => {
                            debug!("daemon stdout EOF");
                            break;
                        }
                        Ok(n) => {
                            if let Err(e) = ws_sink.send(Message::Binary(stdout_buf[..n].to_vec().into())).await {
                                debug!(error = %e, "WebSocket send error");
                                break;
                            }
                        }
                        Err(e) => {
                            debug!(error = %e, "daemon stdout read error");
                            break;
                        }
                    }
                }
            }
        }
    })
    .await;

    if result.is_err() {
        warn!(client = %client, "session timed out");
    }

    // Clean up
    drop(daemon_stdin);
    let _ = child.kill().await;
    let _ = child.wait().await;
    stderr_task.abort();

    info!(client = %client, "relay session ended");
    Ok(())
}
