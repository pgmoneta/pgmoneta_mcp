\newpage

# Configuration

This chapter describes the configuration files that are parsed by
pgmoneta_mcp. The main server configuration is loaded from either the path
specified by the `-c` flag or `/etc/pgmoneta-mcp/pgmoneta-mcp.conf`.

## What this is about

pgmoneta_mcp uses separate configuration files for the server, users, the
native client, and the inspector. The files are INI files, and the
configuration is split into sections using the `[` and `]` characters.

The server reads:

- `pgmoneta-mcp.conf`: MCP server, pgmoneta connection, and optional server-side
  LLM configuration
- `pgmoneta-mcp-users.conf`: encrypted pgmoneta admin passwords

The main section, called `[pgmoneta_mcp]`, is where you configure the overall
properties of the MCP server. The other required server section, called
`[pgmoneta]`, is where you configure the connection with the pgmoneta server.

The native client and inspector read their own configuration files.

## File locations

Default paths:

- Server file: `/etc/pgmoneta-mcp/pgmoneta-mcp.conf`
- Users file: `/etc/pgmoneta-mcp/pgmoneta-mcp-users.conf`
- Native client file: `/etc/pgmoneta-mcp/pgmoneta-mcp-client.conf`
- Inspector file: `/etc/pgmoneta-mcp/pgmoneta-mcp-inspector.conf`

You can override these paths with command-line flags:

``` sh
pgmoneta-mcp-server -c /path/to/pgmoneta-mcp.conf -u /path/to/pgmoneta-mcp-users.conf
pgmoneta-mcp-client -c /path/to/pgmoneta-mcp-client.conf -u /path/to/pgmoneta-mcp-users.conf
pgmoneta-mcp-inspector inspector -c /path/to/pgmoneta-mcp-inspector.conf tool list
```

## Server configuration

`pgmoneta-mcp.conf` configures the MCP server and its connection to pgmoneta.

Example:

``` ini
[pgmoneta_mcp]
port = 8000
log_type = console
log_level = info
log_path = pgmoneta_mcp.log
log_line_prefix = %Y-%m-%d %H:%M:%S
log_mode = append
log_rotation_age = 0

[pgmoneta]
host = localhost
port = 5000
metrics = 5001

[llm]
endpoint = http://localhost:8100/v1
model = ggml-org/gemma-4-E4B-it-GGUF
max_tool_rounds = 10
```

The `[llm]` section is optional. Omit it if you do not use server-side local LLM
integration.

## Section: `[pgmoneta_mcp]`

This section configures the MCP server process.

| Property | Default | Unit | Required | Description |
| :------- | :------ | :--- | :------- | :---------- |
| `port` | `8000` | Int | No | The port the MCP server starts on |
| `log_type` | `console` | String | No | The logging type: `console`, `file`, or `syslog` |
| `log_level` | `info` | String | No | The logging level, any of the strings `trace`, `debug`, `info`, `warn`, and `error` |
| `log_path` | `pgmoneta_mcp.log` | String | No | The log file location |
| `log_line_prefix` | `%Y-%m-%d %H:%M:%S` | String | No | Timestamp format used by the logger |
| `log_mode` | `append` | String | No | Append to or create the log file, any of the strings `append` or `create` |
| `log_rotation_age` | `0` | String | No | The time after which log file rotation is triggered when `log_type = file` and `log_mode = append` |

The server bind address is fixed at `0.0.0.0` in the current implementation.
There is no `[pgmoneta_mcp].host` setting. The MCP endpoint is available at:

``` text
http://<server-host>:<port>/mcp
```

The same port also serves the MCP server's own Prometheus metrics at
`http://<server-host>:<port>/metrics`. This is separate from the `metrics`
port in the `[pgmoneta]` section, which is the pgmoneta server's metrics
endpoint.

`log_rotation_age` accepts:

| Value | Meaning |
| :---- | :------ |
| `0` | Never rotate |
| `m` or `M` | Rotate minutely |
| `h` or `H` | Rotate hourly |
| `d` or `D` | Rotate daily |
| `w` or `W` | Rotate weekly |

When file rotation is enabled, `log_path` is treated as a filename prefix for
rotated files.

### CORS

The MCP server has CORS enabled. The policy is fixed and cannot be changed in
the configuration file:

| CORS setting | Value |
| :----------- | :---- |
| Allowed origins | Any (`*`) |
| Allowed methods | Any |
| Allowed headers | Any |
| Exposed headers | Any |
| Preflight cache (`Access-Control-Max-Age`) | 86400 seconds (24 hours) |

Because any origin is allowed, do not expose the MCP port to untrusted
networks. Restrict access with a firewall, a reverse proxy, or SSH tunneling
instead.

## Section: `[pgmoneta]`

This section configures how pgmoneta_mcp connects to the pgmoneta management
server.

| Property | Default | Unit | Required | Description |
| :------- | :------ | :--- | :------- | :---------- |
| `host` | - | String | Yes | The address of the pgmoneta instance |
| `port` | - | Int | Yes | The port of the pgmoneta instance |
| `metrics` | `5001` | Int | No | The port of the pgmoneta Prometheus metrics endpoint |
| `compression` | `zstd` | String | No | Compression of the traffic to pgmoneta: `none`, `gzip`, `zstd`, `lz4` or `bzip2` |
| `encryption` | `aes_256_gcm` | String | No | Encryption of the traffic to pgmoneta: `none`, `aes_256_gcm`, `aes_192_gcm` or `aes_128_gcm` |

The management `port` must match pgmoneta's `management` setting. The `metrics`
port is separate and should match pgmoneta's Prometheus metrics endpoint.

The `compression` and `encryption` values are used for every request sent to
pgmoneta. The server refuses to start if either value is not one of the listed
options.

## Section: `[llm]`

This optional section configures the local LLM integration for AI-powered
backup management. See the **Local LLM** chapter or
[LOCAL_LLM.md](../../LOCAL_LLM.md) for detailed setup instructions.

| Property | Default | Unit | Required | Description |
| :------- | :------ | :--- | :------- | :---------- |
| `endpoint` | - | String | Yes | OpenAI API URL, normally ending in `/v1` |
| `model` | - | String | Yes | The model name to use for inference |
| `max_tool_rounds` | `10` | Int | No | Maximum tool-calling iterations per user prompt |

When `[llm]` is present, `endpoint` and `model` must not be empty.

## Users configuration

`pgmoneta-mcp-users.conf` stores encrypted passwords for pgmoneta admin users.
The server and native client expect a `[pgmoneta-mcp-users]` section.

Example shape:

``` ini
[pgmoneta-mcp-users]
admin = <encrypted-password>
operator = <encrypted-password>
```

Use `pgmoneta-mcp-admin` to create and update this file. Do not write plaintext
passwords manually.

``` sh
pgmoneta-mcp-admin -f /etc/pgmoneta-mcp/pgmoneta-mcp-users.conf -U admin user add
pgmoneta-mcp-admin -f /etc/pgmoneta-mcp/pgmoneta-mcp-users.conf user ls
```

The encrypted values depend on the master key in
`~/.pgmoneta-mcp/master.key`. The running `pgmoneta-mcp-server` process must use
the same master key that was used when the users file was created or updated.

## Client configuration

`pgmoneta-mcp-client.conf` configures the native client. It is separate from the
server configuration file.

Example:

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

The `[pgmoneta_mcp_client]` section controls the MCP connection.

| Property | Required | Default | Description |
| :------- | :------- | :------ | :---------- |
| `url` | Yes | - | Full MCP endpoint, including `/mcp` |
| `timeout` | No | `30` | Connection and request timeout in seconds |
| `model` | No | - | Default named LLM profile for natural-language requests |
| `confirm` | No | `off` | Ask before running a tool that is not read-only in user mode (`on` or `off`) |

Any other section in the client file is treated as a named LLM profile. In the
example above, `[gemma]` is the profile name. If exactly one profile is present,
the client can select it automatically. If multiple profiles are present,
`[pgmoneta_mcp_client].model` must name the default profile.

Named client LLM profiles use the same keys as `[llm]`:

| Property | Required | Default | Description |
| :------- | :------- | :------ | :---------- |
| `endpoint` | Yes | - | OpenAI API URL |
| `model` | Yes | - | Model identifier |
| `max_tool_rounds` | No | `10` | Maximum tool-calling iterations per prompt |

For user workflows, see [Client](50-client.md).

## Inspector configuration

`pgmoneta-mcp-inspector.conf` configures the inspector.

Example:

``` ini
[inspector]
url = http://localhost:8000/mcp
timeout = 30
```

| Property | Required | Default | Description |
| :------- | :------- | :------ | :---------- |
| `url` | Yes | - | Full MCP endpoint, including `/mcp` |
| `timeout` | No | `30` | Connection and request timeout in seconds |

For user workflows, see [Inspector](51-inspector.md).
