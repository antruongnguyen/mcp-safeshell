mod config;
mod pipeline;
mod platform;
mod sanitizer;
mod server;

use std::env;
use std::net::SocketAddr;
use std::path::Path;

use rmcp::ServiceExt;
use rmcp::transport::StreamableHttpServerConfig;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::tower::StreamableHttpService;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

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
        "stdio" => run_stdio(config).await,
        "http" => {
            let bind_idx = env::args().position(|a| a == "--bind");
            let bind = bind_idx
                .and_then(|i| env::args().nth(i + 1))
                .or_else(|| config.http_bind.clone())
                .unwrap_or_else(|| "127.0.0.1:3456".to_string());
            run_http(&bind, config).await
        }
        other => {
            eprintln!("Unknown transport: {other}. Use 'stdio' or 'http'.");
            std::process::exit(1);
        }
    }
}

async fn run_stdio(config: config::Config) -> anyhow::Result<()> {
    tracing::info!("Starting SafeShell MCP server (stdio transport)");
    let service = server::SafeShellServer::new(config)
        .serve(rmcp::transport::stdio())
        .await
        .inspect_err(|e| tracing::error!("serving error: {:?}", e))?;

    tokio::select! {
        result = service.waiting() => { result?; }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Shutting down (stdio)");
        }
    }
    Ok(())
}

async fn run_http(bind: &str, _config: config::Config) -> anyhow::Result<()> {
    tracing::info!(bind, "Starting SafeShell MCP server (HTTP transport)");
    let addr: SocketAddr = bind.parse()?;

    let mcp_service: StreamableHttpService<server::SafeShellServer, LocalSessionManager> =
        StreamableHttpService::new(
            move || Ok(server::SafeShellServer::new(config::Config::load())),
            LocalSessionManager::default().into(),
            StreamableHttpServerConfig::default(),
        );

    let app = axum::Router::new().nest_service("/mcp", mcp_service);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("Listening on {addr}");

    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            tokio::signal::ctrl_c().await.ok();
            tracing::info!("Shutting down");
        })
        .await?;

    Ok(())
}
