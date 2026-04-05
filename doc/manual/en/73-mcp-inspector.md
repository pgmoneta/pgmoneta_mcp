# pgmoneta-mcp-inspector

## Inspector Configuration File

The `inspector` command reads connection settings from a conf file.

Default path:

```text
/etc/pgmoneta-mcp/pgmoneta-mcp-inspector.conf
```

Expected format:

```ini
[inspector]
url = http://localhost:8000/mcp
timeout = 30
```

## CLI Hierarchy Tree
The following tree visualizes the entire command-line structure.

```text
pgmoneta-mcp-inspector
│
├── inspector (Connect to MCP server)
│   ├── --conf -c <CONF>       (Optional: Inspector config path. Default: /etc/pgmoneta-mcp/pgmoneta-mcp-inspector.conf)
│   │
│   └── tool (Manage and execute MCP tools)
│       ├── list (List all available tools on the server)
│       │   └── --output -o <tree|json> (Default: tree)
│       │
│       └── call (Call a specific tool)
│           ├── <NAME>              (Position 1: Tool name, e.g., get_backup_info)
│           ├── <ARGS>              (Position 2: Strict JSON arguments. Default: "{}")
│           ├── --file -f <PATH>    (Optional: Path file containing JSON arguments)
│           └── --output -o <tree|json> (Default: tree)
│
├── interactive (Default) (launch interactive wizard/shell)
│
└── --help -h                  (Print help information. Available at any level for context-aware help)

```
---

## Commands
 Execute commands directly.

### A. Inspector Example

#### 1. Listing Tools

```bash
./pgmoneta-mcp-inspector inspector --conf <path_to_inspector_conf> tool list
```

#### 2. Calling a Tool

```bash
./pgmoneta-mcp-inspector inspector --conf <path_to_inspector_conf> tool call <tool_name_with_args> '{"key": "value"}'
```
```bash
./pgmoneta-mcp-inspector inspector --conf <path_to_inspector_conf> tool call <tool_name_without_args>
```

> **Note 1:** The `-f` flag allows you to load data from any file. This is functionally identical to typing directly in the terminal.Max file size supported: **10 MB**
> ```bash
> ./pgmoneta-mcp-inspector inspector --conf <path_to_inspector_conf> tool call get_backup_info -f <path_to_args_file>
> ```

---

## Interactive

Built on the command line, that provides a smooth user experience and converting user input into commands and executing them. run it: 

```bash
./pgmoneta-mcp-inspector interactive
```

Or run with no command to enter interactive mode by default:

```bash
./pgmoneta-mcp-inspector
```

> **Note 1 (Strict JSON Inputs):** Because the wizard may assemble a JSON request from your inputs (like the `args` of the `call` tool), every value must be a valid JSON value:
>
> | Type | Rule | Example |
> | :--- | :--- | :--- |
> | String | Must be wrapped in double quotes | `"primary"` |
> | Number | Enter directly | `123` |
> | Boolean | Enter directly | `true` or `false` |
> | Object | Enter full JSON object | `{"key": "value"}` |
> | Array | Enter full JSON array | `["a", "b", "c"]` |
> | Null | Enter null keyword | `null` |
> | Empty (skip) | Leave blank — the key will not be sent | *(press Enter)* |

> **Note 2 (`@path` Injection):** In any argument prompt, type @ followed by a file path to inject the file's content as the value. Max file size supported: **10 MB**.
> ```
> @anypath/file.txt
> ```

> **Note 3 :** You can press **Esc** or **Ctrl+C** during in the interactive wizard to cancel the current action and return to the main menu.