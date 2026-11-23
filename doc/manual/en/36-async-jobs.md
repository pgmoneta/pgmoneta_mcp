\newpage

# Async operations and jobs

Long-running backup operations can run in the background. Set `async` to
`true` when calling `backup`, `restore`, `archive`, or `delete`. pgmoneta then
returns immediately with a job identifier while the operation continues in the
background.

For example, in developer mode:

```text
backup {"server":"primary","async":true}
restore {"server":"primary","backup_id":"latest","directory":"/tmp/restore","async":true}
archive {"server":"primary","backup_id":"latest","directory":"/tmp/archive","async":true}
delete {"server":"primary","backup_id":"oldest","force":false,"async":true}
```

Omitting `async`, or setting it to `false`, preserves the normal synchronous
behavior and waits for the operation to finish.

## Inspect a job by identifier

Use `job` with the identifier returned by an async operation. It returns
the active job when it is still running, or its persisted result after it has
finished.

```text
job {"job_id":"s0-backup-20260920123000"}
```

Running job responses can include the current workflow phase and progress data.
Completed and failed jobs include their persisted outcome.

## Inspect the current or latest operation

Use `job_status` when the identifier is not known. It first returns the matching
currently running job. If no matching job is running, it returns the latest
persisted job for that server and operation.

```text
job_status {"server":"primary","command":"backup"}
job_status {"server":"primary","command":"restore"}
```

The supported command values are `backup`, `restore`, `archive`, and `delete`.

## List jobs

Jobs can be listed across the installation, for one server, or by state:

```text
job_list_all {}
job_list_server {"server":"primary"}
job_list_status {"state":"Running"}
job_list_status {"state":"Completed"}
job_list_status {"state":"Failed"}
```

The supported state values are `Running`, `Completed`, and `Failed`.

## Remove persisted jobs

Remove one persisted job by identifier:

```text
job_remove {"job_id":"s0-backup-20260920123000"}
```

Omit `job_id` to remove all persisted job records:

```text
job_remove {}
```

An active job cannot be removed. Removing a job only removes its job record; it
does not delete the backup or other output produced by the operation.

The MCP client normally injects the authenticated `username` automatically. API
clients calling these tools directly must include it.

## MCP Tasks

pgmoneta-mcp supports the MCP Tasks extension (`io.modelcontextprotocol/tasks`).
When the MCP client declares it, `backup`, `restore`, `archive`, and `delete`
always run as async jobs and answer the tool call with a task. The task ID is
the pgmoneta job identifier.

* `tasks/get` reads the job with `JOB GET`. A running job is `working`, with its
  state and any progress (percentage, done and total, remaining) in the status
  message. A finished job is `completed` and carries the final tool result; a
  failed job sets `isError` on that result.
* `tasks/cancel` is rejected, because pgmoneta cannot cancel a running job yet.

A task can only be read in the MCP session that created it. Clients without
Tasks support keep the behavior described above and use the `job` tools.
