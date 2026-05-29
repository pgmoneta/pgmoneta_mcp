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

//! Integration tests for pgmoneta walinfo functionality
//!
//! These tests verify the complete walinfo workflow including:
//! - Tool registration and metadata
//! - Request/response handling
//! - Data translation and formatting
//! - Error handling

use pgmoneta_mcp::handler::PgmonetaHandler;

#[test]
fn test_walinfo_tool_registration() {
    let tools = PgmonetaHandler::tool_router().list_all();
    let tool_names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();

    // Verify walinfo is registered
    assert!(
        tool_names.contains(&"walinfo"),
        "walinfo tool should be registered in the tool router. Available tools: {:?}",
        tool_names
    );
}

#[test]
fn test_walinfo_tool_metadata() {
    let tools = PgmonetaHandler::tool_router().list_all();
    let walinfo_tool = tools
        .iter()
        .find(|t| t.name == "walinfo")
        .expect("walinfo tool should be found");

    // Verify description exists and contains key terms
    assert!(
        walinfo_tool.description.is_some(),
        "walinfo tool should have a description"
    );
    let description = walinfo_tool.description.as_ref().unwrap();
    assert!(
        description.contains("WAL"),
        "description should mention WAL: {}",
        description
    );
    assert!(
        description.contains("pgmoneta"),
        "description should mention pgmoneta: {}",
        description
    );
}

#[test]
fn test_walinfo_input_schema() {
    use rmcp::model::JsonObject;

    let tools = PgmonetaHandler::tool_router().list_all();
    let walinfo_tool = tools
        .iter()
        .find(|t| t.name == "walinfo")
        .expect("walinfo tool should be found");

    // Verify input schema exists
    let schema_ref = &walinfo_tool.input_schema;
    assert!(
        !schema_ref.is_empty(),
        "walinfo tool should have an input schema"
    );

    // Verify schema has the expected properties
    let schema_obj: &JsonObject = schema_ref.as_ref();
    assert!(
        schema_obj.contains_key("properties"),
        "schema should have properties"
    );

    let properties = schema_obj.get("properties").unwrap().as_object().unwrap();
    assert!(
        properties.contains_key("username"),
        "schema should have username property"
    );
    assert!(
        properties.contains_key("server"),
        "schema should have server property"
    );

    // Verify required fields
    if let Some(required) = schema_obj.get("required") {
        let required_array = required.as_array().unwrap();
        assert!(
            required_array.contains(&"username".into()),
            "username should be required"
        );
        assert!(
            required_array.contains(&"server".into()),
            "server should be required"
        );
    }
}

#[test]
fn test_walinfo_command_constant() {
    use pgmoneta_mcp::constant::Command;

    // Verify the WALINFO command constant exists and has the correct value
    assert_eq!(Command::WALINFO, 25, "WALINFO command should be 25");

    // Verify the command translation works
    let translated = Command::translate_command_enum(Command::WALINFO);
    assert!(
        translated.is_ok(),
        "WALINFO command should translate successfully"
    );
    assert_eq!(translated.unwrap(), "walinfo");
}

#[test]
fn test_walinfo_request_structure() {
    use pgmoneta_mcp::handler::walinfo::WalInfoRequest;

    // Test basic structure
    let request = WalInfoRequest {
        username: "admin".to_string(),
        server: "primary".to_string(),
        ..Default::default()
    };

    assert_eq!(request.username, "admin");
    assert_eq!(request.server, "primary");

    // Test JSON serialization
    let json = serde_json::to_string(&request).expect("should serialize");
    assert!(json.contains("username"));
    assert!(json.contains("server"));
    assert!(json.contains("admin"));
    assert!(json.contains("primary"));

    // Test JSON deserializationq
    let deserialized: WalInfoRequest = serde_json::from_str(&json).expect("should deserialize");
    assert_eq!(deserialized.username, "admin");
    assert_eq!(deserialized.server, "primary");
}

#[test]
fn test_walinfo_tool_base_implementation() {
    use pgmoneta_mcp::handler::walinfo::WalInfoTool;
    use rmcp::handler::server::router::tool::ToolBase;

    // Verify tool name
    assert_eq!(WalInfoTool::name(), "walinfo");

    // Verify description exists
    assert!(WalInfoTool::description().is_some());
    let desc = WalInfoTool::description().unwrap();
    assert!(desc.contains("WAL"));
    assert!(desc.contains("pgmoneta"));

    // Verify output schema is None (for dynamic JSON output)
    assert!(WalInfoTool::output_schema().is_none());
}

#[test]
fn test_walinfo_error_codes_defined() {
    use pgmoneta_mcp::constant::ManagementError;

    // While there are no specific WALINFO error codes yet,
    // this test ensures we're checking the error infrastructure
    let error_msg = ManagementError::translate_error_enum(0);
    assert_eq!(error_msg, "Unknown error");
}

#[test]
fn test_walinfo_integration_with_handler() {
    use pgmoneta_mcp::handler::PgmonetaHandler;
    use rmcp::ServerHandler;

    let handler = PgmonetaHandler::new();
    let info = handler.get_info();

    // Verify handler is properly configured
    assert!(info.capabilities.tools.is_some());
}

#[test]
fn test_walinfo_request_validation() {
    use pgmoneta_mcp::handler::walinfo::WalInfoRequest;

    // Test valid requests
    let valid_requests = vec![
        serde_json::json!({
            "username": "admin",
            "server": "primary"
        }),
        serde_json::json!({
            "username": "alice",
            "server": "standby"
        }),
        serde_json::json!({
            "username": "bob",
            "server": "server1"
        }),
    ];

    for json in valid_requests {
        let request: WalInfoRequest =
            serde_json::from_value(json).expect("should deserialize valid request");
        assert!(!request.username.is_empty());
        assert!(!request.server.is_empty());
    }

    // Test invalid requests (missing fields)
    let invalid_requests = vec![
        serde_json::json!({"username": "admin"}), // missing server
        serde_json::json!({"server": "primary"}), // missing username
        serde_json::json!({}),                    // missing both
    ];

    for json in invalid_requests {
        let result: Result<WalInfoRequest, _> = serde_json::from_value(json.clone());
        assert!(result.is_err(), "should reject invalid request: {}", json);
    }
}
