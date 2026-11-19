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
model = gemma

[gemma]
endpoint = http://localhost:8100/v1
model = ggml-org/gemma-4-E4B-it-GGUF
max_tool_rounds = 10
```

The `[pgmoneta_mcp_client]` section controls the MCP connection:

| Key | Required | Description |
| :-- | :-- | :-- |
| `url` | Yes | Full MCP endpoint, including `/mcp`. |
| `timeout` | No | Connection and request timeout in seconds. Defaults to `30`. |
| `model` | No | Default named LLM profile for natural-language requests. Required when more than one profile is configured. |
| `confirm` | No | Ask before running a tool that is not read-only in user mode, `on` or `off`. Defaults to `off`. See User mode below. |

Each additional section, such as `[qwen]`, is a named LLM profile. The section
name is what you use with `/model`.

| Key | Required | Description |
| :-- | :-- | :-- |
| `endpoint` | Yes | OpenAI API URL, normally ending in `/v1`. |
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
```

The client sends the available tool definitions to the active model, asks it to
choose the matching tool and JSON arguments, executes the tool, and renders the
result. When the request is a general question or cannot be fulfilled using the
available tools, the model answers directly in markdown.

While it waits, the client shows what it is doing and for how long on a line
of its own:

``` text
⠋ Thinking 4s
⠙ Running delete on primary 12s
```

`Thinking` is the model choosing a tool, `Running` is the tool running against
pgmoneta and `Writing the reply` is the model turning the result into the
answer. The line is removed before the answer, a question or an error is
printed, and it is not drawn when the output goes to a pipe or a file.
Developer mode shows it while a tool runs.

With `confirm = on` in `[pgmoneta_mcp_client]`, the client asks before running a
tool that changes something, such as `backup`, `delete` or `restore`. It shows
what the model picked first:

``` text
delete on primary
  backup_id: oldest
? Run it? (y/N)
```

Only `y` runs it. `n`, `Enter`, `Esc` or `Ctrl+C` cancel it and nothing is
sent to pgmoneta. When a request runs several tools, cancelling one skips the
ones after it too. Tools the server marks as read-only, such as `list_backups`
or `get_info`, run without asking, and so does every call in developer mode,
where you type the exact call yourself.

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
```

Switch back to user mode:

``` text
/user
```

## Runtime commands

The interactive shell supports these commands:

``` text
/clear                Clear the screen, leaving only the status banner
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

The commands also have natural-language forms that are handled locally, without
the leading slash and without going to the LLM. `help` prints exactly the same
output as `/help`, and `quit` exits like `/quit`:

``` text
help, show help, show commands             /help
clear, clear screen, clear terminal        /clear
connect, connect to <url>, connect <url>   /connect [url]
disconnect                                 /disconnect
reload client, reconnect                   /reload
user mode, switch to user mode             /user
developer mode, switch to developer mode   /developer
list models, show models, models           /list-models
show model, current model, model           /model
use model <name>, model <name>             /model <name>
switch to model <name>                     /model <name>
list tools, show tools, tools              /tools
quit, exit, bye                            /quit
```

The forms are matched case-insensitively, and the ones taking an argument
accept a single word only, so a longer sentence is still sent to the LLM.
`status` on its own is an MCP tool, so it is not used as a form. `clear` is an
MCP tool too, but on its own it clears the screen; reach the tool with
`clear {}` in developer mode, or with a longer request such as
`clear the prometheus statistics` in user mode.

`/connect [url]` switches the current MCP target. If `[url]` is omitted, the
client reconnects to the configured target from `pgmoneta-mcp-client.conf`.

`/reload` disconnects the current session, restores the configured MCP target
and startup `/model` selection, and reconnects.

`/clear` (or `clear`) clears the screen and the scrollback buffer when attached
to a real terminal and then reprints the current status banner, so the banner is
all that remains.

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

The shell supports readline-style editing and history shortcuts. While typing,
the rest of a matching slash command, natural-language form, or profile name
(after `/model ` or `use model `) is shown as grey ghost text:

* Tab accepts the ghost text, one word at a time for multi-word forms
* Shift+Tab cycles through the other matching candidates
* Right arrow accepts all of the ghost text
* With no ghost text, Tab lists the possible completions

History is stored in:

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

For implementation details, see [Client internals](74-mcp-client.md).
