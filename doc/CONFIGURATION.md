# pgmoneta-mcp configuration

The configuration is loaded from either the path specified by the `-c` flag or `/etc/pgmoneta-mcp/pgmoneta-mcp.conf`.

The configuration of `pgmoneta` is split into sections using the `[` and `]` characters.

The main section, called `[pgmoneta_mcp]`, is where you configure the overall properties
of the MCP server.

The other section, called `[pgmoneta]`, is where you configure connection with `pgmoneta` server.

## [pgmoneta_mcp]

| Property | Default | Unit | Required | Description |
| :------- | :------ | :--- | :------- | :---------- |
| port | 8000 | Int | No | The port MCP server starts on |
| log_type | console | String | No | The logging type (console, file, syslog) |
| log_level | info | String | No | The logging level, any of the strings `trace`, `debug`, `info`, `warn` and `error`|
| log_path | pgmoneta_mcp.log | String | No | The log file location |
| log_mode | append | String | No | Append to or create the log file, any of the strings (`append`, `create`) |
| log_rotation_age | 0 | String | No | The time after which log file rotation is triggered. when `log_type = file` and `log_mode = append`. `log_path` is treated as a filename prefix for rotated files. Any of the chars (`0`) for never rotate, (`m`, `M`) for minutely rotation, (`h`, `H`) for hourly rotation, (`d`, `D`) for daily rotation and (`w`, `W`) for weekly rotation |

## [pgmoneta]

| Property | Default | Unit | Required | Description |
| :------- | :------ | :--- | :------- | :---------- |
| host | | String | Yes | The address of pgmoneta instance |
| port | | Int | Yes | The port of pgmoneta instance |
| base_dir | | String | Yes | The pgmoneta data directory. Required by the `walinfo` tool; WAL files are read from `<base_dir>/<server>/wal`. |
| metrics | 5001 | Int | No | The port of the pgmoneta Prometheus metrics endpoint |

## [llm]

Optional. Configures the local LLM integration for AI-powered backup management.
See the manual or [LOCAL_LLM.md](LOCAL_LLM.md) for detailed setup instructions.

| Property | Default | Unit | Required | Description |
| :------- | :------ | :--- | :------- | :---------- |
| provider | | String | Yes | The local LLM backend (`ollama`, `llama.cpp` or `ramalama`) |
| endpoint | | String | Yes | The URL of the LLM inference server. For `llama.cpp`, `ramalama`, and `vllm`, either the server root URL or the OpenAI-compatible `/v1` URL can be configured |
| model | | String | Yes | The model name to use for inference |
| max_tool_rounds | 10 | Int | No | Maximum tool-calling iterations per user prompt |
