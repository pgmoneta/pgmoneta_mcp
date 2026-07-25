\newpage

# Client

Use the native client when you want a terminal-first interface for pgmoneta_mcp.
It can run natural-language requests through a configured local LLM profile, or
it can call MCP tools directly with JSON arguments.

## What this is about

`pgmoneta-mcp-client` is the day-to-day user shell for pgmoneta_mcp. It connects
to the MCP server, loads users from the users file, injects the selected
`username` automatically, and keeps the interaction focused on backup and
restore work.

The client has two modes:

- User mode: natural-language requests, backed by a configured client LLM
  profile
- Developer mode: explicit MCP tool calls with JSON arguments

Use user mode when you want to ask for outcomes such as "List backups for
primary". Use developer mode when you want exact, repeatable tool calls such as
`list_backups {"server":"primary","sort":"desc"}`.

## Configuration

Create a client configuration file and point it at the MCP endpoint:

``` ini
[pgmoneta_mcp_client]
url = http://localhost:8000/mcp
timeout = 30
model = qwen

[qwen]
provider = ollama
endpoint = http://localhost:11434
model = qwen2.5:3b
max_tool_rounds = 10
```

The `[pgmoneta_mcp_client]` section controls the MCP connection:

| Key | Required | Description |
| :-- | :-- | :-- |
| `url` | Yes | Full MCP endpoint, including `/mcp`. |
| `timeout` | No | Connection and request timeout in seconds. Defaults to `30`. |
| `model` | No | Default named LLM profile for natural-language requests. Required when more than one profile is configured. |

Each additional section, such as `[qwen]`, is a named LLM profile. The section
name is what you use with `/model`.

| Key | Required | Description |
| :-- | :-- | :-- |
| `provider` | Yes | LLM backend, such as `ollama`, `llama.cpp`, `ramalama`, or `vllm`. |
| `endpoint` | Yes | LLM server URL. For OpenAI-compatible runtimes, either the server root URL or `/v1` URL can be used. |
| `model` | Yes | Model name or ID used for tool selection. |
| `max_tool_rounds` | No | Maximum tool-calling iterations per prompt. Defaults to `10`. |

Start the client:

``` sh
pgmoneta-mcp-client -c /etc/pgmoneta-mcp/pgmoneta-mcp-client.conf -u /etc/pgmoneta-mcp/pgmoneta-mcp-users.conf
```

If the users file contains multiple admin users, the client asks you to choose
one at startup.

## User mode

The client starts in user mode. User mode requires a configured client LLM
profile with a reachable endpoint.

Ask directly for the outcome you want:

``` text
Take a backup for server primary
List backups for server primary in descending order
Get information about the latest backup for server primary
Restore the latest backup for server primary to /tmp/pgmoneta-restore
Show WAL activity for server primary around 4:02pm
```

The client sends the available tool definitions to the active model, asks it to
choose the matching tool and JSON arguments, executes the tool, and renders the
result.

Use `/model` to show the active profile and `/model <name>` to switch profiles:

``` text
/model
/model qwen
/list-models
```

## Developer mode

Developer mode sends direct MCP tool calls. It does not require the client LLM
profile to be reachable.

Switch modes:

``` text
/developer
```

Then call tools with strict JSON arguments:

``` text
backup {"server":"primary"}
list_backups {"server":"primary","sort":"desc"}
get_info {"server":"primary","backup_id":"latest"}
restore {"server":"primary","backup_id":"latest","directory":"/tmp/pgmoneta-restore"}
walinfo {"server":"primary"}
walinfo {"server":"primary","time":"4:02pm","window_minutes":10}
```

Switch back to user mode:

``` text
/user
```

For `walinfo`, the client supplies `mode: "user"` in user mode and
`mode: "developer"` in developer mode when it is not specified. Supply `mode`
explicitly to override this behavior.

## Runtime commands

The interactive shell supports these commands:

``` text
/clear                Clear the terminal and reprint the status header
/connect [url]        Connect to [url] or the configured MCP server target
/disconnect           Disconnect from the current MCP server target
/reload               Reconnect with the original client URL and model configuration
/list-models          List configured LLM profiles
/model                Show the active LLM profile
/model <name>         Switch to a configured LLM profile
/help                 Show usage
/user                 Switch to user mode
/developer            Switch to developer mode
/tools                List available MCP tools
/exit or /quit        Exit the client
```

`/connect [url]` switches the current MCP target. If `[url]` is omitted, the
client reconnects to the configured target from `pgmoneta-mcp-client.conf`.

`/reload` disconnects the current session, restores the configured MCP target
and startup `/model` selection, and reconnects.

`/clear` clears the current terminal when attached to a real terminal and then
reprints the current status header.

## Prompt and history

The prompt shows the selected username and current MCP target URL:

``` text
admin@localhost:8000/mcp$
```

The startup header shows MCP reachability and active model endpoint reachability
independently. The header is refreshed after `/clear`, `/connect`,
`/disconnect`, `/reload`, and `/model <name>`.

Non-empty input lines are recorded in history. If the first non-whitespace
character is `#`, the line is treated as a comment, recorded in history, and not
executed.

The shell supports readline-style editing and history shortcuts. Slash commands
support Tab completion, and `/model` supports Tab completion for configured
profile names. History is stored in:

``` text
~/.pgmoneta-mcp/pgmoneta-mcp-client.history
```

The client keeps the latest 1000 history entries. Press Ctrl+C once to show
`Press Ctrl+c again to quit`; press Ctrl+C again within 2 seconds to exit.

## VS Code

If you use VS Code MCP integration, add pgmoneta_mcp as an MCP server entry.

**Prerequisites**

- VS Code installed
- GitHub Copilot extension installed

**Add the server**

1. Open the Command Palette in VS Code (F1 or Ctrl+Shift+P)
2. Type "MCP: Add Server"
3. Configure your server with the following settings:
   - Name: `pgmoneta`
   - URL: `http://localhost:8000/mcp` (adjust host/port as needed)

**Start the server**

1. Go to the Extensions tab
2. Find your pgmoneta MCP server
3. Click the gear icon
4. Choose "Start Server"

**Use the server**

Open a chat (Ctrl + Alt + I) and try:

- "Say hello to the pgmoneta MCP server"
- "Get information about the latest backup for server primary"
- "List all backups for server primary"

## Claude Desktop

Add the following to your Claude Desktop configuration file:

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`

**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

**Linux**: `~/.config/Claude/claude_desktop_config.json`

``` json
{
  "mcpServers": {
    "pgmoneta": {
      "url": "http://localhost:8000/mcp"
    }
  }
}
```

Restart Claude Desktop and the pgmoneta tools will be available.

For implementation details, see [Client internals](73-mcp-client.md).
