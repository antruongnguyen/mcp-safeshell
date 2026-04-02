mod pipeline;
mod platform;
mod server;

use std::env;
use std::net::SocketAddr;

use rmcp::ServiceExt;
use rmcp::transport::StreamableHttpServerConfig;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::tower::StreamableHttpService;
use tracing_subscriber::{EnvFilter, fmt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive(tracing::Level::INFO.into()))
        .with_target(true)
        .json()
        .with_writer(std::io::stderr)
        .init();

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
        "stdio" => run_stdio().await,
        "http" => {
            let bind_idx = env::args().position(|a| a == "--bind");
            let bind = bind_idx
                .and_then(|i| env::args().nth(i + 1))
                .unwrap_or_else(|| "127.0.0.1:3456".to_string());
            run_http(&bind).await
        }
        other => {
            eprintln!("Unknown transport: {other}. Use 'stdio' or 'http'.");
            std::process::exit(1);
        }
    }
}

async fn run_stdio() -> anyhow::Result<()> {
    tracing::info!("Starting SafeShell MCP server (stdio transport)");
    let service = server::SafeShellServer::new()
        .serve(rmcp::transport::stdio())
        .await
        .inspect_err(|e| tracing::error!("serving error: {:?}", e))?;
    service.waiting().await?;
    Ok(())
}

async fn run_http(bind: &str) -> anyhow::Result<()> {
    tracing::info!(bind, "Starting SafeShell MCP server (HTTP transport)");
    let addr: SocketAddr = bind.parse()?;

    let mcp_service: StreamableHttpService<server::SafeShellServer, LocalSessionManager> =
        StreamableHttpService::new(
            || Ok(server::SafeShellServer::new()),
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
