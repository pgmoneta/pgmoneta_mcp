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

use pgmoneta_mcp::constant::ManagementError;
use pgmoneta_mcp::handler::PgmonetaHandler;
use pgmoneta_mcp::handler::archive::{ArchiveRequest, ArchiveTool};
use pgmoneta_mcp::handler::backup::{BackupRequest, BackupServerTool};
use pgmoneta_mcp::handler::delete::{DeleteRequest, DeleteTool};
use pgmoneta_mcp::handler::job::{
    JobCommand, JobListAllRequest, JobListAllTool, JobListByServerRequest, JobListByStateRequest,
    JobListServerTool, JobListStatusTool, JobRemoveRequest, JobRemoveTool, JobRequest, JobState,
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

/// Finds a nested `Outcome` object that reports a failure.
fn find_failed_outcome(value: &Value) -> Option<&Value> {
    match value {
        Value::Object(object) => object
            .get("Outcome")
            .filter(|outcome| outcome["Status"] == false)
            .or_else(|| object.values().find_map(find_failed_outcome)),
        Value::Array(array) => array.iter().find_map(find_failed_outcome),
        _ => None,
    }
}

fn assert_error(response: &Value, code: u32) {
    assert_eq!(response["Outcome"]["Status"], false, "response: {response}");
    assert_eq!(
        response["Outcome"]["Error"],
        ManagementError::translate_error_enum(code),
        "response: {response}"
    );
}

fn job_id_from_ack(response: &str) -> String {
    let acknowledgement = parse_response(response);
    assert_success(&acknowledgement);
    let job_id = find_string(&acknowledgement, "JobId")
        .unwrap_or_else(|| {
            panic!(
                "pgmoneta did not return a job ID for Async: true; rebuild the test image with `test/check.sh integration`: {response}"
            )
        })
        .to_string();
    assert!(!job_id.is_empty());
    job_id
}

/// Polls a job until it reaches `Completed` or `Failed` and returns the final job response.
async fn wait_for_terminal_job(handler: &PgmonetaHandler, job_id: &str) -> Value {
    let deadline = Instant::now() + Duration::from_secs(300);
    loop {
        let response = timeout(
            Duration::from_secs(10),
            JobTool::invoke(
                handler,
                JobRequest {
                    username: USERNAME.to_string(),
                    job_id: job_id.to_string(),
                },
            ),
        )
        .await
        .expect("job lookup timed out")
        .expect("job lookup should succeed");
        let job = parse_response(&response);
        assert_success(&job);
        match find_string(&job, "JobState") {
            Some("Completed" | "Failed") => return job,
            Some("Starting" | "Running") => {}
            state => panic!("job response has unexpected JobState {state:?}: {job}"),
        }
        assert!(
            Instant::now() < deadline,
            "job {job_id} did not finish within 5 minutes"
        );
        sleep(Duration::from_secs(1)).await;
    }
}

async fn wait_for_completed_job(handler: &PgmonetaHandler, job_id: &str) -> Value {
    let job = wait_for_terminal_job(handler, job_id).await;
    assert_eq!(
        find_string(&job, "JobState"),
        Some("Completed"),
        "job: {job}"
    );
    job
}

async fn start_async_backup(handler: &PgmonetaHandler) -> String {
    let response = BackupServerTool::invoke(
        handler,
        BackupRequest {
            username: USERNAME.to_string(),
            server: SERVER.to_string(),
            backup_id: None,
            asynchronous: Some(true),
        },
    )
    .await
    .expect("async backup request should be accepted");
    job_id_from_ack(&response)
}

async fn assert_job_status_contains(handler: &PgmonetaHandler, command: JobCommand, job_id: &str) {
    let status = parse_response(
        &JobStatusTool::invoke(
            handler,
            JobStatusRequest {
                username: USERNAME.to_string(),
                server: SERVER.to_string(),
                command,
            },
        )
        .await
        .expect("job status should succeed"),
    );
    assert_success(&status);
    assert!(
        contains_job_id(&status, job_id),
        "status response: {status}"
    );
}

fn restore_request(backup_id: String, directory: &str) -> RestoreRequest {
    RestoreRequest {
        username: USERNAME.to_string(),
        server: SERVER.to_string(),
        backup_id,
        directory: directory.to_string(),
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
    }
}

/// How many times a conflict test starts a new backup if the first one finishes
/// before the conflicting request reaches pgmoneta.
const CONFLICT_ATTEMPTS: usize = 5;

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
                command: JobCommand::Backup,
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
                state: JobState::Completed,
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
                command: JobCommand::Restore,
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

#[tokio::test]
#[serial_test::serial]
#[ignore = "requires pgmoneta stack (see test/check.sh )"]
async fn async_archive_job_lifecycle_test() {
    let container = common::init_config().await;
    let _guard = common::backup_fixture_lock().await;
    let backup_id = common::ensure_backup(SERVER)
        .await
        .expect("backup fixture should be created");
    let destination = "/tmp/archive_async_job";
    container.ensure_absent(destination).await;

    let handler = PgmonetaHandler::new();
    let response = ArchiveTool::invoke(
        &handler,
        ArchiveRequest {
            username: USERNAME.to_string(),
            server: SERVER.to_string(),
            backup_id,
            directory: destination.to_string(),
            asynchronous: Some(true),
            ..Default::default()
        },
    )
    .await
    .expect("async archive request should be accepted");
    let job_id = job_id_from_ack(&response);

    wait_for_completed_job(&handler, &job_id).await;
    assert_job_status_contains(&handler, JobCommand::Archive, &job_id).await;
    assert!(
        container.is_nonempty(destination).await,
        "archive destination should be non-empty"
    );

    container.ensure_absent(destination).await;
}

#[tokio::test]
#[serial_test::serial]
#[ignore = "requires pgmoneta stack (see test/check.sh )"]
async fn async_delete_job_lifecycle_test() {
    let _container = common::init_config().await;
    let _guard = common::backup_fixture_lock().await;
    let backup_id = common::ensure_backup(SERVER)
        .await
        .expect("backup fixture should be created");

    let handler = PgmonetaHandler::new();
    let response = DeleteTool::invoke(
        &handler,
        DeleteRequest {
            username: USERNAME.to_string(),
            server: SERVER.to_string(),
            backup_id: backup_id.clone(),
            force: Some(true),
            asynchronous: Some(true),
        },
    )
    .await
    .expect("async delete request should be accepted");
    let job_id = job_id_from_ack(&response);

    wait_for_completed_job(&handler, &job_id).await;
    assert_job_status_contains(&handler, JobCommand::Delete, &job_id).await;

    // The deleted backup can no longer be deleted.
    let again = parse_response(
        &DeleteTool::invoke(
            &handler,
            DeleteRequest {
                username: USERNAME.to_string(),
                server: SERVER.to_string(),
                backup_id,
                force: Some(true),
                asynchronous: None,
            },
        )
        .await
        .expect("second delete should return a management response"),
    );
    assert_eq!(again["Outcome"]["Status"], false, "response: {again}");
}

#[tokio::test]
#[serial_test::serial]
#[ignore = "requires pgmoneta stack (see test/check.sh )"]
async fn async_restore_job_failed_test() {
    let _container = common::init_config().await;
    let _guard = common::backup_fixture_lock().await;
    let backup_id = common::ensure_backup(SERVER)
        .await
        .expect("backup fixture should be created");

    let handler = PgmonetaHandler::new();

    // /proc is not writable even by root, so the restore fails after the job has started.
    let response = RestoreTool::invoke(
        &handler,
        restore_request(backup_id, "/proc/pgmoneta_mcp_restore_failed_job"),
    )
    .await
    .expect("async restore request should be accepted");
    let job_id = job_id_from_ack(&response);

    let job = wait_for_terminal_job(&handler, &job_id).await;
    assert_eq!(find_string(&job, "JobState"), Some("Failed"), "job: {job}");
    let outcome = find_failed_outcome(&job["Response"])
        .unwrap_or_else(|| panic!("failed job should persist a failed outcome: {job}"));
    let error = outcome["Error"]
        .as_str()
        .unwrap_or_else(|| panic!("failed outcome should carry a translated error: {job}"));
    assert!(!error.is_empty(), "job: {job}");
    assert_ne!(error, "Unknown error", "job: {job}");

    let failed_jobs = parse_response(
        &JobListStatusTool::invoke(
            &handler,
            JobListByStateRequest {
                username: USERNAME.to_string(),
                state: JobState::Failed,
            },
        )
        .await
        .expect("listing failed jobs should succeed"),
    );
    assert_success(&failed_jobs);
    assert!(
        contains_job_id(&failed_jobs, &job_id),
        "failed jobs response: {failed_jobs}"
    );
}

#[tokio::test]
#[serial_test::serial]
#[ignore = "requires pgmoneta stack (see test/check.sh )"]
async fn job_remove_all_test() {
    let _container = common::init_config().await;
    let _guard = common::backup_fixture_lock().await;
    let handler = PgmonetaHandler::new();

    let job_id = start_async_backup(&handler).await;
    wait_for_completed_job(&handler, &job_id).await;

    let removed = parse_response(
        &JobRemoveTool::invoke(
            &handler,
            JobRemoveRequest {
                username: USERNAME.to_string(),
                job_id: None,
            },
        )
        .await
        .expect("removing all jobs should succeed"),
    );
    assert_success(&removed);

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
        find_string(&all_jobs, "JobId").is_none(),
        "no job records should remain: {all_jobs}"
    );

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
    assert_error(&missing, ManagementError::MANAGEMENT_ERROR_JOB_NOT_FOUND);
}

/// Removing a job while it is still running is rejected with "job is active" (3202).
/// pgmoneta defines 3205 (`JOB_REMOVE_ACTIVE`) but does not send it.
#[tokio::test]
#[serial_test::serial]
#[ignore = "requires pgmoneta stack (see test/check.sh )"]
async fn job_remove_active_job_test() {
    let _container = common::init_config().await;
    let _guard = common::backup_fixture_lock().await;
    let handler = PgmonetaHandler::new();

    for attempt in 1..=CONFLICT_ATTEMPTS {
        let job_id = start_async_backup(&handler).await;
        let removed = parse_response(
            &JobRemoveTool::invoke(
                &handler,
                JobRemoveRequest {
                    username: USERNAME.to_string(),
                    job_id: Some(job_id.clone()),
                },
            )
            .await
            .expect("job remove should return a management response"),
        );

        if removed["Outcome"]["Status"] == true {
            // The backup finished before the remove arrived; try again.
            eprintln!("attempt {attempt}: backup {job_id} finished before the remove");
            continue;
        }

        assert_error(&removed, ManagementError::MANAGEMENT_ERROR_JOB_ACTIVE);
        // The rejected remove must not disturb the running job.
        wait_for_completed_job(&handler, &job_id).await;
        return;
    }
    panic!("backup finished before job_remove in all {CONFLICT_ATTEMPTS} attempts");
}

/// A second operation on a server with a running job is rejected by that
/// operation's own "active" error (here BACKUP_ACTIVE, 102), not by a job error.
#[tokio::test]
#[serial_test::serial]
#[ignore = "requires pgmoneta stack (see test/check.sh )"]
async fn operation_while_job_running_test() {
    let _container = common::init_config().await;
    let _guard = common::backup_fixture_lock().await;
    let handler = PgmonetaHandler::new();

    for attempt in 1..=CONFLICT_ATTEMPTS {
        let job_id = start_async_backup(&handler).await;
        let second = parse_response(
            &BackupServerTool::invoke(
                &handler,
                BackupRequest {
                    username: USERNAME.to_string(),
                    server: SERVER.to_string(),
                    backup_id: None,
                    asynchronous: Some(true),
                },
            )
            .await
            .expect("second backup should return a management response"),
        );

        if second["Outcome"]["Status"] == true {
            // The first backup finished before the second arrived; try again.
            eprintln!("attempt {attempt}: backup {job_id} finished before the second backup");
            wait_for_terminal_job(&handler, &job_id).await;
            if let Some(second_id) = find_string(&second, "JobId") {
                wait_for_terminal_job(&handler, second_id).await;
            }
            continue;
        }

        assert_error(&second, ManagementError::MANAGEMENT_ERROR_BACKUP_ACTIVE);
        wait_for_completed_job(&handler, &job_id).await;
        return;
    }
    panic!("first backup finished before the second in all {CONFLICT_ATTEMPTS} attempts");
}
