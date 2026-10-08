use pgmoneta_mcp::handler::PgmonetaHandler;
use pgmoneta_mcp::handler::info::{ListBackupsRequest, ListBackupsTool};
use rmcp::handler::server::router::tool::AsyncTool;
use serde_json::Value;
use serial_test::serial;
mod common;
#[tokio::test]
#[serial]
#[ignore = "requires pgmoneta stack (see test/check.sh and full-test CI job)"]
async fn list_backup_test() {
    let _container = common::init_config().await;
    let _guard = common::backup_fixture_lock().await;
    common::ensure_backup("primary")
        .await
        .expect("backup fixture should be created");

    let handler = PgmonetaHandler::new();
    let info_request = ListBackupsRequest {
        username: "backup_user".to_string(),
        server: "primary".to_string(),
        sort: Some("asc".to_string()),
    };

    let response = ListBackupsTool::invoke(&handler, info_request)
        .await
        .expect("list_backups should succeed");

    let json: Value = serde_json::from_str(&response).expect("response should be valid json");

    if let Some(header) = json.get("Header") {
        if let Some(command) = header.get("Command") {
            assert!(command.is_string(), "Command should be a string");
            assert!(command == "list-backup", "Command should be 'list-backup'");
        } else {
            panic!("Command field missing in Header");
        }
    } else {
        panic!("Header field missing");
    };

    if let Some(outcome) = json.get("Outcome") {
        if let Some(status) = outcome.get("Status") {
            assert!(status.is_boolean(), "Status should be a boolean");
            assert!(status == true, "Status should be true");
        } else {
            panic!("Status field missing in Outcome");
        }
    } else {
        panic!("Outcome field missing");
    };
}
