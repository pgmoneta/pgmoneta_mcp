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

use pgmoneta_mcp::handler::PgmonetaHandler;
use pgmoneta_mcp::handler::backup::{BackupRequest, BackupServerTool};
use pgmoneta_mcp::handler::job::{
    JobListAllRequest, JobListAllTool, JobListByServerRequest, JobListByStateRequest,
    JobListServerTool, JobListStatusTool, JobRemoveRequest, JobRemoveTool, JobRequest,
    JobStatusRequest, JobStatusTool, JobTool,
};
use pgmoneta_mcp::handler::restore::{RestoreRequest, RestoreTool};
use rmcp::handler::server::router::tool::AsyncTool;
use serde_json::Value;
use tokio::time::{Duration, Instant, sleep, timeout};

mod common;

const USERNAME: &str = "backup_user";
const SERVER: &str = "primary";

fn parse_response(response: &str) -> Value {
    serde_json::from_str(response)
        .unwrap_or_else(|error| panic!("response should be valid JSON ({error}): {response}"))
}

fn assert_success(response: &Value) {
    assert_eq!(response["Outcome"]["Status"], true, "response: {response}");
}

fn find_string<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    match value {
        Value::Object(object) => object
            .get(key)
            .and_then(Value::as_str)
            .or_else(|| object.values().find_map(|value| find_string(value, key))),
        Value::Array(array) => array.iter().find_map(|value| find_string(value, key)),
        _ => None,
    }
}

fn contains_job_id(value: &Value, job_id: &str) -> bool {
    match value {
        Value::Object(object) => {
            object.get("JobId").and_then(Value::as_str) == Some(job_id)
                || object.values().any(|value| contains_job_id(value, job_id))
        }
        Value::Array(array) => array.iter().any(|value| contains_job_id(value, job_id)),
        _ => false,
    }
}

#[tokio::test]
#[serial_test::serial]
#[ignore = "requires pgmoneta stack (see test/check.sh )"]
async fn async_backup_job_lifecycle_test() {
    let _container = common::init_config().await;
    let _guard = common::backup_fixture_lock().await;
    let handler = PgmonetaHandler::new();

    // Start the documented async operation and capture its immediate job acknowledgement.
    let response = BackupServerTool::invoke(
        &handler,
        BackupRequest {
            username: USERNAME.to_string(),
            server: SERVER.to_string(),
            backup_id: None,
            asynchronous: Some(true),
        },
    )
    .await
    .expect("async backup request should be accepted");
    let acknowledgement = parse_response(&response);
    assert_success(&acknowledgement);
    let job_id = acknowledgement["Response"]["JobId"]
        .as_str()
        .unwrap_or_else(|| {
            panic!(
                "pgmoneta did not return a job ID for Async: true; rebuild the test image with `test/check.sh integration`: {response}"
            )
        })
        .to_string();
    assert!(!job_id.is_empty());

    // Job lookup can return a running job or its persisted result, so wait for a terminal state.
    let deadline = Instant::now() + Duration::from_secs(300);
    let completed_job = loop {
        let response = JobTool::invoke(
            &handler,
            JobRequest {
                username: USERNAME.to_string(),
                job_id: job_id.clone(),
            },
        )
        .await
        .expect("job lookup should succeed");
        let job = parse_response(&response);
        assert_success(&job);
        match find_string(&job, "JobState") {
            Some("Completed") => break job,
            Some("Failed") => panic!("async backup job failed: {job}"),
            Some("Starting" | "Running") => {}
            state => panic!("job response has unexpected JobState {state:?}: {job}"),
        }
        assert!(
            Instant::now() < deadline,
            "job did not finish within 5 minutes"
        );
        sleep(Duration::from_secs(1)).await;
    };
    assert_eq!(find_string(&completed_job, "JobState"), Some("Completed"));

    let status = parse_response(
        &JobStatusTool::invoke(
            &handler,
            JobStatusRequest {
                username: USERNAME.to_string(),
                server: SERVER.to_string(),
                command: "backup".to_string(),
            },
        )
        .await
        .expect("job status should succeed"),
    );
    assert_success(&status);
    assert!(
        contains_job_id(&status, &job_id),
        "status response: {status}"
    );

    let all_jobs = parse_response(
        &JobListAllTool::invoke(
            &handler,
            JobListAllRequest {
                username: USERNAME.to_string(),
            },
        )
        .await
        .expect("listing all jobs should succeed"),
    );
    assert_success(&all_jobs);
    assert!(
        contains_job_id(&all_jobs, &job_id),
        "all jobs response: {all_jobs}"
    );

    let server_jobs = parse_response(
        &JobListServerTool::invoke(
            &handler,
            JobListByServerRequest {
                username: USERNAME.to_string(),
                server: SERVER.to_string(),
            },
        )
        .await
        .expect("listing jobs for a server should succeed"),
    );
    assert_success(&server_jobs);
    assert!(
        contains_job_id(&server_jobs, &job_id),
        "server jobs response: {server_jobs}"
    );

    let completed_jobs = parse_response(
        &JobListStatusTool::invoke(
            &handler,
            JobListByStateRequest {
                username: USERNAME.to_string(),
                state: "Completed".to_string(),
            },
        )
        .await
        .expect("listing completed jobs should succeed"),
    );
    assert_success(&completed_jobs);
    assert!(
        contains_job_id(&completed_jobs, &job_id),
        "completed jobs response: {completed_jobs}"
    );

    let removed = parse_response(
        &JobRemoveTool::invoke(
            &handler,
            JobRemoveRequest {
                username: USERNAME.to_string(),
                job_id: Some(job_id.clone()),
            },
        )
        .await
        .expect("removing a completed job should succeed"),
    );
    assert_success(&removed);

    let missing = parse_response(
        &JobTool::invoke(
            &handler,
            JobRequest {
                username: USERNAME.to_string(),
                job_id,
            },
        )
        .await
        .expect("missing-job lookup should return a management response"),
    );
    assert_eq!(missing["Outcome"]["Status"], false, "response: {missing}");
}

#[tokio::test]
#[serial_test::serial]
#[ignore = "requires pgmoneta stack (see test/check.sh )"]
async fn async_restore_job_lifecycle_test() {
    let container = common::init_config().await;
    let _guard = common::backup_fixture_lock().await;
    let backup_id = common::ensure_backup(SERVER)
        .await
        .expect("backup fixture should be created");
    let destination = "/tmp/restore_async_job";
    container.ensure_absent(destination).await;
    assert!(!container.exists(destination).await);

    let handler = PgmonetaHandler::new();

    let response = RestoreTool::invoke(
        &handler,
        RestoreRequest {
            username: USERNAME.to_string(),
            server: SERVER.to_string(),
            backup_id,
            directory: destination.to_string(),
            asynchronous: Some(true),
            current: None,
            name: None,
            xid: None,
            time: None,
            lsn: None,
            inclusive: None,
            timeline: None,
            action: None,
            primary: None,
            replica: None,
        },
    )
    .await
    .expect("async restore request should be accepted");
    let acknowledgement = parse_response(&response);
    assert_success(&acknowledgement);
    let job_id = acknowledgement["Response"]["JobId"]
        .as_str()
        .or_else(|| find_string(&acknowledgement, "JobId"))
        .unwrap_or_else(|| {
            panic!(
                "pgmoneta did not return a job ID for Async: true; rebuild the test image with `test/check.sh integration`: {response}"
            )
        })
        .to_string();
    assert!(!job_id.is_empty());

    let deadline = Instant::now() + Duration::from_secs(300);
    let completed_job = loop {
        let response = timeout(
            Duration::from_secs(10),
            JobTool::invoke(
                &handler,
                JobRequest {
                    username: USERNAME.to_string(),
                    job_id: job_id.clone(),
                },
            ),
        )
        .await
        .expect("job lookup timed out")
        .expect("job lookup should succeed");
        let job = parse_response(&response);
        assert_success(&job);
        match find_string(&job, "JobState") {
            Some("Completed") => break job,
            Some("Failed") => panic!("async restore job failed: {job}"),
            Some("Starting" | "Running") => {}
            state => panic!("job response has unexpected JobState {state:?}: {job}"),
        }
        assert!(
            Instant::now() < deadline,
            "job did not finish within 5 minutes"
        );
        sleep(Duration::from_secs(1)).await;
    };
    assert_eq!(find_string(&completed_job, "JobState"), Some("Completed"));

    let status = parse_response(
        &JobStatusTool::invoke(
            &handler,
            JobStatusRequest {
                username: USERNAME.to_string(),
                server: SERVER.to_string(),
                command: "restore".to_string(),
            },
        )
        .await
        .expect("job status should succeed"),
    );
    assert_success(&status);
    assert!(
        contains_job_id(&status, &job_id),
        "status response: {status}"
    );

    assert!(
        container.exists(destination).await,
        "destination should exist"
    );
    assert!(
        container.is_nonempty(destination).await,
        "destination should be non-empty"
    );

    container.ensure_absent(destination).await;
    assert!(
        !container.exists(destination).await,
        "destination should be cleaned up"
    );
}
