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

use clap::Parser;
use pgmoneta_mcp::configuration;
use pgmoneta_mcp::handler::PgmonetaHandler;
use rmcp::transport::streamable_http_server::{
    StreamableHttpService, session::local::LocalSessionManager,
};
use tracing_subscriber::{self, EnvFilter};

const BIND_ADDRESS: &str = "0.0.0.0";

#[derive(Debug, Parser)]
#[command(
    name = "pgmoneta-mcp",
    about = "A Model Context Protocol (MCP) server for pgmoneta, backup/restore tool for PostgreSQL"
)]
struct Args {
    /// Path to pgmoneta MCP configuration file
    #[arg(short = 'c', long)]
    conf: String,

    /// Path to pgmoneta MCP users configuration file
    #[arg(short = 'u', long)]
    users: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let config = configuration::load_configuration(&args.conf, &args.users)?;
    let address = format!("{BIND_ADDRESS}:{}", &config.pgmoneta_mcp.port);
    configuration::CONFIG
        .set(config)
        .expect("CONFIG already initialized");

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive(tracing::Level::DEBUG.into()))
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();
    let handler = StreamableHttpService::new(
        || Ok(PgmonetaHandler::new()),
        LocalSessionManager::default().into(),
        Default::default(),
    );

    let router = axum::Router::new().nest_service("/mcp", handler);
    let tcp_listener = tokio::net::TcpListener::bind(&address).await?;

    println!("Starting pgmoneta MCP server at {address}");

    let _ = axum::serve(tcp_listener, router)
        .with_graceful_shutdown(async { tokio::signal::ctrl_c().await.unwrap() })
        .await;
    Ok(())
}
