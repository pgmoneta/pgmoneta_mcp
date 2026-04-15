// Copyright (C) 2026 The pgmoneta community
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
use pgmoneta_mcp::logging::Logger;
use rmcp::transport::streamable_http_server::{
    StreamableHttpService, session::local::LocalSessionManager,
};
use std::time::Duration;
use tower_http::cors::{Any, CorsLayer};

const BIND_ADDRESS: &str = "0.0.0.0";

#[derive(Debug, Parser)]
#[command(
    name = "pgmoneta-mcp",
    about = "A Model Context Protocol (MCP) server for pgmoneta, backup/restore tool for PostgreSQL"
)]
struct Args {
    /// Path to pgmoneta MCP configuration file
    #[arg(
        short = 'c',
        long,
        default_value = "/etc/pgmoneta-mcp/pgmoneta-mcp.conf"
    )]
    conf: String,

    /// Path to pgmoneta MCP users configuration file
    #[arg(
        short = 'u',
        long,
        default_value = "/etc/pgmoneta-mcp/pgmoneta-mcp-users.conf"
    )]
    users: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let config = configuration::load_configuration(&args.conf, &args.users)?;
    let address = format!("{BIND_ADDRESS}:{}", &config.pgmoneta_mcp.port);

    let _guard = Logger::init(
        config.pgmoneta_mcp.log_level.as_str(),
        config.pgmoneta_mcp.log_type.as_str(),
        config.pgmoneta_mcp.log_line_prefix.as_str(),
        config.pgmoneta_mcp.log_path.as_str(),
        config.pgmoneta_mcp.log_mode.as_str(),
        config.pgmoneta_mcp.log_rotation_age.as_str(),
    );

    let handler = StreamableHttpService::new(
        || Ok(PgmonetaHandler::new()),
        LocalSessionManager::default().into(),
        Default::default(),
    );

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any)
        .expose_headers(Any)
        .max_age(Duration::from_secs(86400));

    let router = axum::Router::new()
        .nest_service("/mcp", handler)
        .layer(cors);
    let tcp_listener = tokio::net::TcpListener::bind(&address).await?;

    configuration::CONFIG
        .set(config)
        .expect("CONFIG already initialized");

    tracing::info!("Starting MCP server at {address}");

    let _ = axum::serve(tcp_listener, router)
        .with_graceful_shutdown(async { tokio::signal::ctrl_c().await.unwrap() })
        .await;
    Ok(())
}
