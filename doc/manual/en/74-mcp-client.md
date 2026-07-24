\newpage

# Client internals

This chapter is developer-facing. It describes how `pgmoneta-mcp-client`
turns terminal input into MCP tool calls, how it manages user and model context,
and where to make changes safely.

## Runtime flow

The client starts by loading:

- `pgmoneta-mcp-client.conf` for the MCP URL, timeout, and named LLM profiles
- `pgmoneta-mcp-users.conf` for selectable pgmoneta_mcp users
- `~/.pgmoneta-mcp/pgmoneta-mcp-client.history` for command history

The high-level loop is:

1. Read a line from the terminal
2. Record non-empty input in history
3. Handle comments and slash commands
4. Parse user-mode or developer-mode input
5. Inject selected user context where the MCP API requires it
6. Execute the MCP tool call
7. Render either translated user output or full JSON output

The prompt follows the selected user and current MCP target. The status header
tracks MCP reachability separately from active model endpoint reachability.

## Modes

**User mode**

User mode accepts natural-language requests. The client sends available tool
definitions to the active LLM profile and asks the model to choose a tool and
produce JSON arguments. The client then validates and executes that tool call.

User mode requires a configured and reachable LLM profile. When multiple LLM
profiles exist, `[pgmoneta_mcp_client].model` selects the startup profile.

**Developer mode**

Developer mode accepts direct tool calls:

``` text
list_backups {"server":"primary","sort":"desc"}
```

Developer mode bypasses the LLM and prints the full JSON response. This is the
preferred path for debugging schemas, adding tests, and documenting exact tool
behavior.

## Command handling

Slash commands are handled before tool execution:

``` text
/clear
/connect [url]
/disconnect
/reload
/list-models
/model
/model <name>
/help
/user
/developer
/tools
/exit
/quit
```

`/connect [url]` changes the current MCP target. `/connect` without a URL
returns to the configured target. `/reload` restores the configured target and
startup model selection, then reconnects.

Tab completion is available for slash commands and configured model names.
Ctrl+C uses a two-step quit guard so one accidental interrupt does not exit the
session.

## Context injection

The MCP API requires `username` for pgmoneta operations. The client selects a
user from the users file and injects that `username` automatically before tool
dispatch. This keeps normal client prompts focused on pgmoneta-specific
arguments such as `server`, `backup_id`, `directory`, and `sort`.

The client derives display context from the configured MCP endpoint and updates
that context when `/connect`, `/disconnect`, or `/reload` changes the current
session.

## Rendering

User mode favors readable output. Known pgmoneta fields are translated into
friendlier values where possible, including file sizes, LSNs, compression and
encryption values, command codes, and error codes.

Developer mode favors exact output. It prints the full JSON response so schema
changes and tool behavior can be inspected directly.

Metric rendering has one special case: in user mode, a single matching metric
can be shown as just its value; in developer mode, the full Prometheus sample
line is shown.

## Extension checklist

When adding or changing a tool:

1. Add or modify the server-side handler and tool registry.
2. Update the tool schema and argument validation.
3. Verify user-mode tool selection still maps natural language to the expected
   tool and JSON arguments.
4. Verify developer-mode invocation still accepts strict JSON and renders the
   response correctly.
5. Add or update tests around parsing, execution, and output formatting.
6. Update the user-facing tool chapter and any client examples that mention the
   changed behavior.
