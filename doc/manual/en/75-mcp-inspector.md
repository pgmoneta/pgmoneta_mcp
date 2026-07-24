\newpage

# Inspector internals

This chapter is developer-facing. It describes how `pgmoneta-mcp-inspector`
maps CLI input and interactive prompts to MCP requests.

## Command structure

The command tree is:

``` text
pgmoneta-mcp-inspector
|
|-- inspector
|   |-- --conf -c <CONF>
|   `-- tool
|       |-- list
|       |   `-- --output -o <tree|json>
|       `-- call
|           |-- <NAME>
|           |-- <ARGS>
|           |-- --file -f <PATH>
|           `-- --output -o <tree|json>
|
|-- interactive
`-- --help
```

If no command is provided, the inspector launches interactive mode.

## Runtime flow

Command mode follows this flow:

1. Parse the CLI command tree with `clap`
2. Load `[inspector]` configuration
3. Connect to the configured MCP endpoint
4. Run `list_tools` or `call_tool`
5. Render the result as tree or JSON
6. Clean up the MCP client session

Interactive mode follows this flow:

1. Prompt for the inspector configuration path
2. Connect once and show server information
3. Let the user list tools or select a tool to call
4. Build arguments from the selected tool schema
5. Execute the call and render tree output
6. Return to the menu until the user exits

## Argument parsing

`tool call` accepts either inline strict JSON or a JSON file:

``` sh
pgmoneta-mcp-inspector inspector --conf <CONF> tool call get_info '{"server":"primary","backup_id":"latest"}'
pgmoneta-mcp-inspector inspector --conf <CONF> tool call get_info -f /tmp/get-info.json
```

The file path uses `SafeFileReader` and is limited to 10 MB.

Interactive mode prompts once per schema property. Empty input skips the key.
Non-empty input must parse as JSON. A value starting with `@` is treated as a
file path and the file content is parsed as the JSON value for that property.

## Output formatting

The inspector serializes MCP responses to JSON values, recursively decodes JSON
strings when possible, and then renders one of two output formats:

- `tree`: ASCII tree output for terminal inspection
- `json`: pretty JSON output for scripts and automation

Long plain strings are truncated in tree rendering after 100 characters to keep
terminal output readable.

## Extension checklist

When adding or changing inspector behavior:

1. Keep command names and argument names stable unless there is a migration
   reason to change them.
2. Ensure `tool list` can discover new server-side tools through the MCP schema.
3. Validate `tool call` with inline JSON and `--file` JSON.
4. Validate interactive prompts against the tool schema.
5. Add or update tests for argument parsing and output formatting.
6. Update the user-facing Inspector chapter when behavior changes.
