\newpage

# Inspector

Use the inspector when you want a structured way to discover MCP tools, inspect
their schemas, and call them with explicit JSON. It is useful for validating
tools, troubleshooting requests, and preparing exact examples for automation or
documentation.

## What this is about

`pgmoneta-mcp-inspector` connects to the same MCP server as the native client,
but it does not perform natural-language interpretation. It lists tools and
executes direct tool calls.

The inspector has two ways of working:

- Command mode: run one `tool list` or `tool call` command and exit
- Interactive mode: choose tools from prompts and fill arguments guided by the
  tool schema

Use the native client for day-to-day backup work. Use the inspector when you
want the exact tool names, schemas, arguments, and raw output.

## Configuration

Create an inspector configuration file:

``` ini
[inspector]
url = http://localhost:8000/mcp
timeout = 30
```

The default path is:

``` text
/etc/pgmoneta-mcp/pgmoneta-mcp-inspector.conf
```

The configuration keys are:

| Key | Required | Description |
| :-- | :-- | :-- |
| `url` | Yes | Full MCP endpoint, including `/mcp`. |
| `timeout` | No | Connection and request timeout in seconds. Defaults to `30`. |

## List tools

List available tools:

``` sh
pgmoneta-mcp-inspector inspector --conf /etc/pgmoneta-mcp/pgmoneta-mcp-inspector.conf tool list
```

The default output format is an ASCII tree. Use JSON output when you want a
machine-readable result:

``` sh
pgmoneta-mcp-inspector inspector --conf /etc/pgmoneta-mcp/pgmoneta-mcp-inspector.conf tool list --output json
```

## Call tools

Call a tool with inline strict JSON:

``` sh
pgmoneta-mcp-inspector inspector --conf /etc/pgmoneta-mcp/pgmoneta-mcp-inspector.conf tool call get_info '{"server":"primary","backup_id":"latest"}'
```

Call a tool with no arguments:

``` sh
pgmoneta-mcp-inspector inspector --conf /etc/pgmoneta-mcp/pgmoneta-mcp-inspector.conf tool call ping
```

Load arguments from a JSON file:

``` sh
pgmoneta-mcp-inspector inspector --conf /etc/pgmoneta-mcp/pgmoneta-mcp-inspector.conf tool call get_info -f /tmp/get-info.json
```

The argument file can be up to 10 MB.

## Interactive mode

Start the interactive wizard:

``` sh
pgmoneta-mcp-inspector interactive
```

Or run without a command to enter interactive mode by default:

``` sh
pgmoneta-mcp-inspector
```

Interactive mode asks for the configuration path, connects to the MCP server,
then lets you list tools or call a selected tool. When calling a tool, it uses
the tool schema to prompt for each argument.

Every entered value must be valid JSON:

| Type | Input example |
| :-- | :-- |
| String | `"primary"` |
| Number | `123` |
| Boolean | `true` or `false` |
| Object | `{"key":"value"}` |
| Array | `["a","b","c"]` |
| Null | `null` |
| Empty | Press Enter to skip the key |

In any argument prompt, type `@` followed by a file path to use the file content
as the value:

``` text
@/tmp/tool-value.json
```

Press Esc or Ctrl+C during the interactive wizard to cancel the current action
and return to the previous menu.

## Example workflow

Start by listing the tools:

``` sh
pgmoneta-mcp-inspector inspector --conf /etc/pgmoneta-mcp/pgmoneta-mcp-inspector.conf tool list
```

Then call a tool using the schema you inspected:

``` sh
pgmoneta-mcp-inspector inspector --conf /etc/pgmoneta-mcp/pgmoneta-mcp-inspector.conf tool call list_backups '{"server":"primary","sort":"desc"}'
```

Use JSON output if you want to pipe the response into another tool:

``` sh
pgmoneta-mcp-inspector inspector --conf /etc/pgmoneta-mcp/pgmoneta-mcp-inspector.conf tool call list_backups '{"server":"primary","sort":"desc"}' --output json
```

For implementation details, see [Inspector internals](75-mcp-inspector.md).
