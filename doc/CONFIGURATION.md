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
| log_line_prefix | %Y-%m-%d %H:%M:%S | String | No | The timestamp format used by the logger |
| log_mode | append | String | No | Append to or create the log file, any of the strings (`append`, `create`) |
| log_rotation_age | 0 | String | No | The time after which log file rotation is triggered. when `log_type = file` and `log_mode = append`. `log_path` is treated as a filename prefix for rotated files. Any of the chars (`0`) for never rotate, (`m`, `M`) for minutely rotation, (`h`, `H`) for hourly rotation, (`d`, `D`) for daily rotation and (`w`, `W`) for weekly rotation |

The MCP endpoint is served at `http://<host>:<port>/mcp`. The same port also
serves the MCP server's own Prometheus metrics at `/metrics`.

### CORS

CORS is enabled with a fixed policy that is not configurable: any origin, any
method, any header and any exposed header are allowed, and preflight responses
are cached for 24 hours (`Access-Control-Max-Age: 86400`). Since any origin is
allowed, do not expose the MCP port to untrusted networks.

## [pgmoneta]

| Property | Default | Unit | Required | Description |
| :------- | :------ | :--- | :------- | :---------- |
| host | | String | Yes | The address of pgmoneta instance |
| port | | Int | Yes | The port of pgmoneta instance |
| metrics | 5001 | Int | No | The port of the pgmoneta Prometheus metrics endpoint |
| compression | zstd | String | No | Compression of the traffic to pgmoneta: `none`, `gzip`, `zstd`, `lz4` or `bzip2` |
| encryption | aes_256_gcm | String | No | Encryption of the traffic to pgmoneta: `none`, `aes_256_gcm`, `aes_192_gcm` or `aes_128_gcm` |

## [llm]

Optional. Configures the local LLM integration for AI-powered backup management.
See the manual or [LOCAL_LLM.md](LOCAL_LLM.md) for detailed setup instructions.

| Property | Default | Unit | Required | Description |
| :------- | :------ | :--- | :------- | :---------- |
| endpoint | | String | Yes | The OpenAI API URL, normally ending in `/v1` |
| model | | String | Yes | The model name to use for inference |
| max_tool_rounds | 10 | Int | No | Maximum tool-calling iterations per user prompt |
