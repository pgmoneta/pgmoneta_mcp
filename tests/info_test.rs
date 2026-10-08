// mod common;
use pgmoneta_mcp::handler::PgmonetaHandler;
use pgmoneta_mcp::handler::info::{GetBackupInfoTool, InfoRequest};
use rmcp::handler::server::router::tool::AsyncTool;
use serde_json::Value;
use serial_test::serial;
mod common;
#[tokio::test]
#[serial]
#[ignore = "requires pgmoneta stack (see test/check.sh and full-test CI job)"]
async fn info_test() {
    let _container = common::init_config().await;
    let _guard = common::backup_fixture_lock().await;
    let backup_id = common::ensure_backup("primary")
        .await
        .expect("backup fixture should be created");

    let handler = PgmonetaHandler::new();
    let info_request = InfoRequest {
        username: "backup_user".to_string(),
        server: "primary".to_string(),
        backup_id,
    };

    let response = GetBackupInfoTool::invoke(&handler, info_request)
        .await
        .expect("get_backup_info should succeed");

    let json: Value = serde_json::from_str(&response).expect("response should be valid json");

    if let Some(header) = json.get("Header") {
        if let Some(command) = header.get("Command") {
            assert!(command.is_string(), "Command should be a string");
            assert!(command == "info", "Command should be 'info'");
        } else {
            panic!("Command field missing in Header");
        }
    } else {
        panic!("Header field missing");
    };
}
