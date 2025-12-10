// Copyright (C) 2025 The pgmoneta community
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use rmcp::transport::streamable_http_server::{
    StreamableHttpService, session::local::LocalSessionManager,
};
use tracing_subscriber::{self, EnvFilter};
use clap::Parser;
mod common;
use common::handler::PgmonetaHandler;
use common::configuration;

const BIND_ADDRESS: &str = "0.0.0.0";

#[derive(Debug, Parser)]
#[command(
    name = "pgmoneta-mcp",
    about = "Start an MCP server for Pgmoneta, backup/restore tool for Postgres"
)]
struct Args {
    /// Path to pgmoneta users configuration file
    #[arg(short, long, default_value = "/etc/pgmoneta_mcp/pgmoneta_mcp_users.toml")]
    users: String,

    /// Path to pgmoneta MCP configuration file
    #[arg(short, long, default_value = "/etc/pgmoneta_mcp/pgmoneta_mcp.toml")]
    conf: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let config = configuration::load_configuration(&args.conf, &args.users)?;
    let address = format!("{BIND_ADDRESS}:{}", &config.port);
    configuration::CONFIG.set(config).expect("CONFIG already initialized");
    
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive(tracing::Level::DEBUG.into()))
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();
    let info_service = StreamableHttpService::new(
        || Ok(PgmonetaHandler::new()),
        LocalSessionManager::default().into(),
        Default::default()
    );
    
    let router = axum::Router::new()
        .nest_service("/mcp", info_service);
    let tcp_listener = tokio::net::TcpListener::bind(address).await?;
    let _ = axum::serve(tcp_listener, router)
        .with_graceful_shutdown(async { tokio::signal::ctrl_c().await.unwrap() })
        .await;
    Ok(())
}
