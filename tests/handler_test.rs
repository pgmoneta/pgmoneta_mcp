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

//! Integration tests for pgmoneta_mcp handler
//!
//! These tests verify core functionality without requiring a running pgmoneta server.
//! They focus on testing public APIs and basic initialization for handlers.

use pgmoneta_mcp::handler::PgmonetaHandler;
use rmcp::ServerHandler;

#[test]
fn test_handler_initialization() {
    let handler = PgmonetaHandler::new();

    // Verify handler can be created
    let info = handler.get_info();

    // Check server info
    assert!(info.instructions.is_some());
    let instructions = info.instructions.unwrap();
    assert!(instructions.contains("pgmoneta"));

    // Verify capabilities
    assert!(info.capabilities.tools.is_some());
}

#[test]
fn test_handler_default_trait() {
    let handler1 = PgmonetaHandler::new();
    let handler2 = PgmonetaHandler::new();

    // Both should produce valid handlers
    let info1 = handler1.get_info();
    let info2 = handler2.get_info();

    assert!(info1.instructions.is_some());
    assert!(info2.instructions.is_some());
}

#[test]
fn test_walinfo_tool_is_available() {
    let tools = PgmonetaHandler::tool_router().list_all();
    let tool_names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();

    // Verify walinfo is registered
    assert!(
        tool_names.contains(&"walinfo"),
        "walinfo tool should be in available tools, found: {:?}",
        tool_names
    );

    // Verify walinfo has a description
    let walinfo_tool = tools
        .iter()
        .find(|t| t.name == "walinfo")
        .expect("walinfo tool not found");
    assert!(
        walinfo_tool
            .description
            .as_ref()
            .map(|d| d.contains("WAL"))
            .unwrap_or(false),
        "walinfo tool should have a description containing 'WAL'"
    );
}
