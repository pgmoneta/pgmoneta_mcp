\newpage

# WAL information

**Natural language description**

Show PostgreSQL Write-Ahead Log (WAL) activity for a pgmoneta server.

**Example**

``` text
Show WAL activity for primary around 4:02pm
```

## Tool: /walinfo

**Tool description**

Reads the server's WAL files with `pgmoneta-walinfo` and returns either a
human-readable transaction timeline or the underlying records as JSON.

**Prerequisites**

- Configure `[pgmoneta].base_dir` to pgmoneta's data directory.
- The WAL directory `<base_dir>/<server>/wal` must exist.
- `pgmoneta-walinfo` must be available in the MCP server process's `PATH`.

**Arguments**

- `server`: The pgmoneta server name.
- Optional `mode`: `user` for the transaction timeline (default), or
  `developer` for raw JSON records.
- Optional `time`: A time of day to filter around. Accepted formats include
  `4:02pm`, `4pm`, `16:02`, `13:24:57`, and `4:02:30pm`.
- Optional `window_minutes`: Minutes on either side of `time` to include.
  Defaults to `5`.

`username` is required by the MCP API and is typically injected by
`pgmoneta-mcp-client`.

**Behavior**

- Without `time`, the tool includes all available WAL records.
- With `time`, it finds transactions with a timestamp inside the selected time
  window and returns every record belonging to those transaction IDs.
- User mode groups records by transaction ID and marks transactions as
  committed or open. System records are counted but not listed individually.
- Developer mode returns a JSON string with `Outcome.Status`,
  `Outcome.Command`, and `Response.WAL`, which contains the filtered records.

**Examples**

``` text
walinfo {"server":"primary"}
walinfo {"server":"primary","time":"4:02pm","window_minutes":10}
walinfo {"server":"primary","mode":"developer","time":"16:02"}
```
