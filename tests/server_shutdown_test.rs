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

use std::time::Duration;

use pgmoneta_mcp::handler::PgmonetaHandler;
use rmcp::{
    ServiceExt,
    transport::streamable_http_client::StreamableHttpClientTransport,
    transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
    },
};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn test_server_shutdown_completes_with_connected_client() {
    let shutdown = CancellationToken::new();
    let service = StreamableHttpService::new(
        || Ok(PgmonetaHandler::new()),
        LocalSessionManager::default().into(),
        StreamableHttpServerConfig::default()
            .with_sse_keep_alive(None)
            .with_cancellation_token(shutdown.child_token()),
    );

    let router = axum::Router::new().nest_service("/mcp", service);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener should bind");
    let addr = listener
        .local_addr()
        .expect("listener should have local addr");

    let server_handle = tokio::spawn({
        let shutdown = shutdown.clone();
        async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async move { shutdown.cancelled_owned().await })
                .await
                .expect("server should shut down cleanly");
        }
    });

    let client = ()
        .serve(StreamableHttpClientTransport::from_uri(format!(
            "http://{addr}/mcp"
        )))
        .await
        .expect("client should connect");

    client
        .list_tools(None)
        .await
        .expect("connected client should be usable");

    shutdown.cancel();

    timeout(Duration::from_secs(5), server_handle)
        .await
        .expect("server shutdown should not wait for connected clients")
        .expect("server task should finish successfully");
}
