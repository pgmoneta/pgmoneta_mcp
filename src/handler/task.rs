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

//! MCP Tasks (SEP-2663) backed by pgmoneta async jobs.
//!
//! When the client declares the tasks extension, `backup`, `restore`,
//! `archive` and `delete` run as pgmoneta async jobs and answer `tools/call`
//! with a task whose ID is the pgmoneta job ID. `tasks/get` then reads the
//! job with `JOB GET`. Clients without tasks support keep the normal tool
//! results and can still use the `job_*` tools.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use rmcp::ErrorData as McpError;
use rmcp::model::{
    CallToolResult, ContentBlock, DetailedTask, JsonObject, Task, TaskPayload, TaskStatus,
};
use serde_json::Value;

/// Tools that can run as a pgmoneta async job and so can return a task.
pub const TASK_TOOLS: [&str; 4] = ["backup", "restore", "archive", "delete"];

/// Suggested `tasks/get` polling interval, in milliseconds.
pub const TASK_POLL_INTERVAL_MS: u64 = 2_000;

/// Returns `true` if `tool` can return a task.
pub fn is_task_tool(tool: &str) -> bool {
    TASK_TOOLS.contains(&tool)
}

#[derive(Debug, Clone)]
struct TaskEntry {
    username: String,
    created_at: String,
}

/// The tasks created in one MCP session.
///
/// Every pgmoneta request needs a username, but `tasks/get` only carries the
/// task ID, so the username is remembered here. A handler is created per
/// session, so a client can only see the tasks it created itself.
#[derive(Debug, Clone, Default)]
pub struct JobTasks {
    entries: Arc<Mutex<HashMap<String, TaskEntry>>>,
}

impl JobTasks {
    /// Remembers a new task and returns its seed state.
    pub fn register(&self, job_id: &str, username: &str) -> Task {
        let now = chrono::Utc::now().to_rfc3339();
        self.lock().insert(
            job_id.to_string(),
            TaskEntry {
                username: username.to_string(),
                created_at: now.clone(),
            },
        );
        Task::new(job_id, TaskStatus::Working, now.clone(), now)
            .with_poll_interval_ms(TASK_POLL_INTERVAL_MS)
    }

    /// Returns the username and creation time of a task from this session.
    pub fn lookup(&self, task_id: &str) -> Result<(String, String), McpError> {
        self.lock()
            .get(task_id)
            .map(|entry| (entry.username.clone(), entry.created_at.clone()))
            .ok_or_else(|| McpError::invalid_params(format!("Unknown task: {task_id}"), None))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, TaskEntry>> {
        // A poisoned lock only means another request panicked mid-insert;
        // the map itself is still usable.
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// Finds the first string value stored under `key`, searching nested objects and arrays.
pub fn find_string<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    match value {
        Value::Object(object) => object
            .get(key)
            .and_then(Value::as_str)
            .or_else(|| object.values().find_map(|value| find_string(value, key))),
        Value::Array(array) => array.iter().find_map(|value| find_string(value, key)),
        _ => None,
    }
}

/// Finds the first value stored under `key`, searching nested objects and arrays.
fn find_value<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    match value {
        Value::Object(object) => object
            .get(key)
            .or_else(|| object.values().find_map(|value| find_value(value, key))),
        Value::Array(array) => array.iter().find_map(|value| find_value(value, key)),
        _ => None,
    }
}

/// Returns the text of the first text block of a tool result.
pub fn result_text(result: &CallToolResult) -> Option<&str> {
    result
        .content
        .iter()
        .find_map(|block| block.as_text().map(|text| text.text.as_str()))
}

/// Builds a short progress line from the job's progress fields, if any are present.
fn progress_message(job: &Value) -> Option<String> {
    let field = |key: &str| {
        find_value(job, key).map(|value| match value {
            Value::String(text) => text.clone(),
            other => other.to_string(),
        })
    };
    let mut parts = Vec::new();
    if let Some(percentage) = field("Percentage") {
        parts.push(format!("{percentage}%"));
    }
    match (field("Done"), field("Total")) {
        (Some(done), Some(total)) => parts.push(format!("{done}/{total} done")),
        (Some(done), None) => parts.push(format!("{done} done")),
        _ => {}
    }
    if let Some(remaining) = field("Remaining") {
        parts.push(format!("{remaining} remaining"));
    }
    (!parts.is_empty()).then(|| parts.join(", "))
}

/// Turns a translated `JOB GET` response into the task state for `tasks/get`.
///
/// A job that finished, whether it succeeded or failed, is a completed task
/// carrying the final tool result; a failed job sets `isError` on that result,
/// as the spec asks for tool calls that ran but reported an error.
pub fn detailed_task(task_id: &str, created_at: &str, job_json: &str) -> DetailedTask {
    let now = chrono::Utc::now().to_rfc3339();
    let job: Value = serde_json::from_str(job_json).unwrap_or(Value::Null);
    let state = find_string(&job, "JobState");

    let mut task = Task::new(task_id, TaskStatus::Working, created_at, now)
        .with_poll_interval_ms(TASK_POLL_INTERVAL_MS);

    let payload = match state {
        Some("Completed") => TaskPayload::Completed {
            result: tool_result_object(CallToolResult::success(vec![ContentBlock::text(job_json)])),
        },
        Some("Failed") => TaskPayload::Completed {
            result: tool_result_object(CallToolResult::error(vec![ContentBlock::text(job_json)])),
        },
        _ => {
            let state = state.unwrap_or("Unknown");
            task.status_message = Some(match progress_message(&job) {
                Some(progress) => format!("{state}: {progress}"),
                None => state.to_string(),
            });
            TaskPayload::Working
        }
    };
    DetailedTask::new(task, payload)
}

fn tool_result_object(result: CallToolResult) -> JsonObject {
    match serde_json::to_value(result) {
        Ok(Value::Object(object)) => object,
        _ => JsonObject::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_task_tools() {
        for tool in ["backup", "restore", "archive", "delete"] {
            assert!(is_task_tool(tool));
        }
        for tool in ["job", "verify", "info", ""] {
            assert!(!is_task_tool(tool));
        }
    }

    #[test]
    fn test_register_and_lookup() {
        let tasks = JobTasks::default();
        let task = tasks.register("primary-backup-1", "admin");
        assert_eq!(task.task_id, "primary-backup-1");
        assert_eq!(task.status, TaskStatus::Working);
        assert_eq!(task.poll_interval_ms, Some(TASK_POLL_INTERVAL_MS));

        let (username, created_at) = tasks.lookup("primary-backup-1").unwrap();
        assert_eq!(username, "admin");
        assert_eq!(created_at, task.created_at);
    }

    #[test]
    fn test_lookup_unknown_task() {
        let tasks = JobTasks::default();
        assert!(tasks.lookup("not-mine").is_err());
    }

    #[test]
    fn test_tasks_are_per_session() {
        let first = JobTasks::default();
        let second = JobTasks::default();
        first.register("job-1", "admin");
        assert!(first.lookup("job-1").is_ok());
        assert!(second.lookup("job-1").is_err());
        // Clones share the session's tasks.
        assert!(first.clone().lookup("job-1").is_ok());
    }

    #[test]
    fn test_running_job_is_working_with_progress() {
        let job = json!({
            "Outcome": {"Status": true},
            "Response": {
                "JobId": "j1",
                "JobState": "Running",
                "Done": 9,
                "Total": 20,
                "Percentage": 45,
                "Remaining": "30s"
            }
        });
        let task = detailed_task("j1", "2026-11-23T00:00:00Z", &job.to_string());
        assert_eq!(task.status(), TaskStatus::Working);
        assert_eq!(task.payload, TaskPayload::Working);
        assert_eq!(
            task.task.status_message.as_deref(),
            Some("Running: 45%, 9/20 done, 30s remaining")
        );
        assert_eq!(task.task.created_at, "2026-11-23T00:00:00Z");
    }

    #[test]
    fn test_starting_job_without_progress() {
        let job = json!({"Outcome": {"Status": true}, "Response": {"JobState": "Starting"}});
        let task = detailed_task("j1", "t", &job.to_string());
        assert_eq!(task.status(), TaskStatus::Working);
        assert_eq!(task.task.status_message.as_deref(), Some("Starting"));
    }

    #[test]
    fn test_completed_job_carries_tool_result() {
        let job = json!({"Outcome": {"Status": true}, "Response": {"JobState": "Completed"}});
        let task = detailed_task("j1", "t", &job.to_string());
        assert_eq!(task.status(), TaskStatus::Completed);
        let TaskPayload::Completed { result } = &task.payload else {
            panic!("expected completed payload: {task:?}");
        };
        let result: CallToolResult = serde_json::from_value(Value::Object(result.clone())).unwrap();
        assert_ne!(result.is_error, Some(true));
        assert_eq!(result_text(&result), Some(job.to_string().as_str()));
    }

    #[test]
    fn test_failed_job_is_completed_with_error() {
        let job = json!({"Outcome": {"Status": true}, "Response": {"JobState": "Failed"}});
        let task = detailed_task("j1", "t", &job.to_string());
        assert_eq!(task.status(), TaskStatus::Completed);
        let TaskPayload::Completed { result } = &task.payload else {
            panic!("expected completed payload: {task:?}");
        };
        assert_eq!(result.get("isError"), Some(&json!(true)));
    }

    #[test]
    fn test_unparsable_job_stays_working() {
        let task = detailed_task("j1", "t", "not json");
        assert_eq!(task.status(), TaskStatus::Working);
        assert_eq!(task.task.status_message.as_deref(), Some("Unknown"));
    }
}
