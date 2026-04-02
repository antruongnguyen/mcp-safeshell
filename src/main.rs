mod config;
mod pipeline;
mod platform;
mod sanitizer;
mod server;
mod shutdown;

use std::env;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use rmcp::ServiceExt;
use rmcp::transport::StreamableHttpServerConfig;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::tower::StreamableHttpService;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

use shutdown::ChildTracker;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = config::Config::load();

    let log_filter = config
        .log_level
        .as_deref()
        .and_then(|s| s.parse::<EnvFilter>().ok())
        .unwrap_or_else(|| {
            EnvFilter::from_default_env().add_directive(tracing::Level::INFO.into())
        });

    let stderr_layer = fmt::layer()
        .with_target(true)
        .json()
        .with_writer(std::io::stderr);

    // Optional log file layer — non-blocking append via tracing-appender.
    let _file_guard;
    if let Some(ref log_path) = config.log_file {
        let path = Path::new(log_path);
        let dir = path.parent().unwrap_or(Path::new("."));
        let filename = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let file_appender = tracing_appender::rolling::never(dir, filename);
        let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
        _file_guard = Some(guard);

        let file_layer = fmt::layer()
            .with_target(true)
            .json()
            .with_writer(non_blocking);

        tracing_subscriber::registry()
            .with(log_filter)
            .with(stderr_layer)
            .with(file_layer)
            .init();
    } else {
        _file_guard = None;
        tracing_subscriber::registry()
            .with(log_filter)
            .with(stderr_layer)
            .init();
    }

    // Install signal handlers and create the shared child tracker.
    let mut shutdown_signal = shutdown::install_signal_handler();
    let child_tracker = Arc::new(ChildTracker::new());

    let transport_arg = env::args().nth(1).unwrap_or_default();

    match transport_arg.as_str() {
        "--transport" | "" => {}
        other => {
            eprintln!("Unknown argument: {other}");
            eprintln!("Usage: safeshell-mcp [--transport stdio|http] [--bind ADDR]");
            std::process::exit(1);
        }
    }

    let mode = env::args().nth(2).unwrap_or_else(|| "stdio".to_string());

    match mode.as_str() {
        "stdio" => run_stdio(config, &mut shutdown_signal, &child_tracker).await,
        "http" => {
            let bind_idx = env::args().position(|a| a == "--bind");
            let bind = bind_idx
                .and_then(|i| env::args().nth(i + 1))
                .or_else(|| config.http_bind.clone())
                .unwrap_or_else(|| "127.0.0.1:3456".to_string());
            run_http(&bind, config, &mut shutdown_signal, &child_tracker).await
        }
        other => {
            eprintln!("Unknown transport: {other}. Use 'stdio' or 'http'.");
            std::process::exit(1);
        }
    }
    // _file_guard drops here, flushing any buffered log entries.
}

async fn run_stdio(
    config: config::Config,
    shutdown_signal: &mut shutdown::ShutdownSignal,
    child_tracker: &Arc<ChildTracker>,
) -> anyhow::Result<()> {
    tracing::info!("Starting SafeShell MCP server (stdio transport)");
    let service = server::SafeShellServer::with_child_tracker(config, Arc::clone(child_tracker))
        .serve(rmcp::transport::stdio())
        .await
        .inspect_err(|e| tracing::error!("serving error: {:?}", e))?;

    tokio::select! {
        result = service.waiting() => { result?; }
        _ = shutdown_signal.recv() => {
            tracing::info!("Shutting down (stdio)");
        }
    }

    child_tracker.kill_all();
    tracing::info!("All child processes terminated, exit clean");
    Ok(())
}

async fn run_http(
    bind: &str,
    _config: config::Config,
    shutdown_signal: &mut shutdown::ShutdownSignal,
    child_tracker: &Arc<ChildTracker>,
) -> anyhow::Result<()> {
    tracing::info!(bind, "Starting SafeShell MCP server (HTTP transport)");
    let addr: SocketAddr = bind.parse()?;

    let tracker = Arc::clone(child_tracker);
    let mcp_service: StreamableHttpService<server::SafeShellServer, LocalSessionManager> =
        StreamableHttpService::new(
            move || {
                Ok(server::SafeShellServer::with_child_tracker(
                    config::Config::load(),
                    Arc::clone(&tracker),
                ))
            },
            LocalSessionManager::default().into(),
            StreamableHttpServerConfig::default(),
        );

    let app = axum::Router::new().nest_service("/mcp", mcp_service);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("Listening on {addr}");

    let mut sig = shutdown_signal.clone();
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            sig.recv().await;
            tracing::info!("Shutting down HTTP server");
        })
        .await?;

    child_tracker.kill_all();
    tracing::info!("All child processes terminated, exit clean");
    Ok(())
}
