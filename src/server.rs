// Copyright (C) 2025 The pgmoneta community
//
// Redistribution and use in source and binary forms, with or without modification,
// are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list
// of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this
// list of conditions and the following disclaimer in the documentation and/or other
// materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may
// be used to endorse or promote products derived from this software without specific
// prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
// OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
// OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
// TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
use rmcp::transport::streamable_http_server::{
    StreamableHttpService, session::local::LocalSessionManager,
};
use tracing_subscriber::{self, EnvFilter};
use clap::Parser;
mod common;
use common::info::Info;
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
        || Ok(Info::new()),
        LocalSessionManager::default().into(),
        Default::default()
    );
    
    let router = axum::Router::new()
        .nest_service("/info", info_service);
    let tcp_listener = tokio::net::TcpListener::bind(address).await?;
    let _ = axum::serve(tcp_listener, router)
        .with_graceful_shutdown(async { tokio::signal::ctrl_c().await.unwrap() })
        .await;
    Ok(())
}
