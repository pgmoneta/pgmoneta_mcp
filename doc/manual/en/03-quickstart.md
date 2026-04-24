\newpage

# Quick start

Make sure that [**pgmoneta_mcp**][pgmoneta_mcp] is installed and in your path by using `pgmoneta-mcp-server --help`. You should see

``` console
A Model Context Protocol (MCP) server for pgmoneta, backup/restore tool for PostgreSQL

Usage: pgmoneta-mcp-server [OPTIONS]

Options:
  -c, --conf <CONF>    Path to pgmoneta MCP configuration file [default: /etc/pgmoneta-mcp/pgmoneta-mcp.conf]
  -u, --users <USERS>  Path to pgmoneta MCP users configuration file [default: /etc/pgmoneta-mcp/pgmoneta-mcp-users.conf]
  -h, --help           Print help
  -V, --version        Print version
```

If you encounter any issues following the above steps, you can refer to the **Installation** chapter to see how to install or compile pgmoneta_mcp on your system.

## Prerequisites

You need to have PostgreSQL 14+ and pgmoneta installed and running. See pgmoneta's [manual](https://github.com/pgmoneta/pgmoneta/tree/main/doc/manual/en) on how to install and run pgmoneta.

**Important**: You need to run pgmoneta in remote admin mode with management enabled. This allows pgmoneta_mcp to communicate with the pgmoneta server.

In your pgmoneta configuration (`pgmoneta.conf`), ensure you have:

``` ini
[pgmoneta]
management = 5000
```

And start pgmoneta with the admins file:

``` sh
pgmoneta -A pgmoneta_admins.conf -c pgmoneta.conf -u pgmoneta_users.conf
```

## Configuration

### Master Key

First, copy the pgmoneta master key into the MCP home directory. This key is
used to encrypt admin passwords stored in the MCP user configuration file.

``` sh
mkdir -p ~/.pgmoneta-mcp
cp ~/.pgmoneta/master.key ~/.pgmoneta-mcp/master.key
chmod 600 ~/.pgmoneta-mcp/master.key
```

Do this before creating or updating `pgmoneta-mcp-users.conf`. The running
`pgmoneta-mcp-server` process must use the same `~/.pgmoneta-mcp/master.key`
that was used when this users file was created or updated.

### User Configuration

Add an admin user to pgmoneta_mcp. This should be the same user you configured in pgmoneta's admins file.

``` sh
pgmoneta-mcp-admin -f pgmoneta-mcp-users.conf -U admin user add
```

You will be prompted for the password. Alternatively, use the `-P` flag:

``` sh
pgmoneta-mcp-admin -f pgmoneta-mcp-users.conf -U admin -P secretpassword user add
```

The password will be encrypted using the master key and stored in `pgmoneta-mcp-users.conf`.

If the server runs under a different OS user or `HOME`, copy the same key into
that user's `~/.pgmoneta-mcp/master.key` before starting the server, otherwise
password decryption will fail when executing tools.

### Server Configuration

Create a configuration file called `pgmoneta-mcp.conf` with the following content:

``` ini
[pgmoneta_mcp]
port = 8000
log_type = file
log_level = info
log_path = /tmp/pgmoneta_mcp.log

[pgmoneta]
host = localhost
port = 5000
```

**Configuration options**:

- `port`: Port where the MCP server will listen (default: 8000)
- `log_type`: Logging destination - `file`, `console`, or `syslog` (default: `console`)
- `log_level`: Log level - `trace`, `debug`, `info`, `warn`, or `error` (default: `info`)
- `log_path`: Path to log file (when `log_type = file`)
- `log_mode`: Append to or create the log file - `append` or `create` (default: `append`)
- `log_rotation_age`: Log rotation interval - `0` (never), `m` (minutely), `h` (hourly), `d` (daily), or `w` (weekly) (default: `0`)
- `[pgmoneta]` section:
  - `host`: Hostname where pgmoneta server is running
  - `port`: Management port of pgmoneta server (must match pgmoneta's `management` setting)
  - `compression`: Compression algorithm for MCP ↔ pgmoneta communication - `none`, `gzip`, `zstd`, `lz4`, or `bzip2` (default: `zstd`)
  - `encryption`: Encryption algorithm for MCP ↔ pgmoneta communication - `none`, `aes_256_gcm`, `aes_192_gcm`, or `aes_128_gcm` (default: `aes_256_gcm`)

See the **Configuration** chapter for all configuration options.

## Running

Start the MCP server using:

``` sh
pgmoneta-mcp-server -c pgmoneta-mcp.conf -u pgmoneta-mcp-users.conf
```

If this doesn't give an error, the MCP server is running and ready to accept connections.

The server can be stopped by pressing Ctrl-C (`^C`) in the console where you started it, or by sending the `SIGTERM` signal to the process using `kill <pid>`.

## Administration

[**pgmoneta_mcp**][pgmoneta_mcp] has an administration tool called `pgmoneta-mcp-admin`, which is used to manage user accounts.

You can see the commands it supports by using `pgmoneta-mcp-admin --help` which will give:

``` console
Administration utility for pgmoneta-mcp

Usage: pgmoneta-mcp-admin [OPTIONS] <COMMAND>

Commands:
  user  Manage a specific user
  help  Print this message or the help of the given subcommand(s)

Options:
  -f, --file <FILE>          The user configuration file
  -U, --user <USER>          The user name
  -P, --password <PASSWORD>  The password for the user
  -h, --help                 Print help
  -V, --version              Print version
```

### Master Key Preparation

Before using `pgmoneta-mcp-admin user ...`, copy the pgmoneta master key into
the MCP home directory:

``` sh
mkdir -p ~/.pgmoneta-mcp
cp ~/.pgmoneta/master.key ~/.pgmoneta-mcp/master.key
chmod 600 ~/.pgmoneta-mcp/master.key
```

### User Management

**Add a user**:

``` sh
pgmoneta-mcp-admin -f pgmoneta-mcp-users.conf -U admin user add
```

**List all users**:

``` sh
pgmoneta-mcp-admin -f pgmoneta-mcp-users.conf user ls
```

**Edit a user's password**:

``` sh
pgmoneta-mcp-admin -f pgmoneta-mcp-users.conf -U admin user edit
```

**Delete a user**:

``` sh
pgmoneta-mcp-admin -f pgmoneta-mcp-users.conf -U admin user del
```

### Browser-based MCP Clients

The MCP server includes built-in CORS (Cross-Origin Resource Sharing) support, so browser-based MCP clients can connect directly without a proxy. Point any web-based MCP client to the server endpoint (e.g., `http://localhost:8000/mcp`).

See the [llama.cpp](22-llama-cpp.md) chapter for a step-by-step Web UI example.

## Using the Client

[**pgmoneta_mcp**][pgmoneta_mcp] provides a built-in interactive client to execute tools and interact with the server.

Start the client by running:

``` sh
pgmoneta-mcp-client -c pgmoneta-mcp-client.conf -u pgmoneta-mcp-users.conf
```

The client reads its connection settings from a dedicated configuration file.
See the **pgmoneta-mcp-client** chapter for all client configuration options.

By default, the client runs in "User mode", which allows you to interact with pgmoneta using natural language, provided you have configured an LLM (see "Using a local LLM" below). 

For example, you can try:
- "List all backups for server primary"
- "Get information about the latest backup for server primary"

If you don't have an LLM configured, or if you prefer to see raw JSON outputs, you can switch to developer mode:

``` console
> /developer
Switched to developer mode.
> list_backups {"server": "primary"}
```

```json
{
    "Header": {
        "ClientVersion": "0.21.0",
        "Command": "list-backup",
        "Compression": "zstd",
        "Encryption": "aes_256_gcm",
        "Output": 1,
        "Timestamp": 20260424162246
    },
    "Outcome": {
        "Status": true,
        "Time": "00:00:0.0059"
    },
    "Request": {
        "Server": "primary",
        "Sort": "asc"
    },
    "Response": {
        "Backups": [
            {
                "Backup": 20260424094135,
                "BackupSize": "8.30 MB",
                "BiggestFileSize": "328.00 KB",
                "Comments": "",
                "Compression": "zstd",
                "Encryption": "aes_256_gcm",
                "Incremental": false,
                "IncrementalParent": "",
                "Keep": false,
                "RestoreSize": "8.29 MB",
                "Server": "primary",
                "Valid": 1,
                "WAL": 0
            }
        ],
        "MajorVersion": 18,
        "MinorVersion": 3,
        "NumberOfBackups": 1,
        "Server": "primary",
        "ServerVersion": "0.21.0"
    }
}
```

``` console
> get_backup_info {"server": "primary", "backup_id": "latest"}
```

```json
{
    "Header": {
        "ClientVersion": "0.21.0",
        "Command": "info",
        "Compression": "zstd",
        "Encryption": "aes_256_gcm",
        "Output": 1,
        "Timestamp": 20260424200750
    },
    "Outcome": {
        "Status": true,
        "Time": "00:00:0.0062"
    },
    "Request": {
        "Backup": "latest",
        "Server": "primary"
    },
    "Response": {
        "Backup": 20260424094452,
        "BackupSize": "5.29 MB",
        "BiggestFileSize": "328.00 KB",
        "CheckpointHiLSN": "0x0",
        "CheckpointLoLSN": "0x22000080",
        "Comments": "",
        "Compression": "zstd",
        "Elapsed": 0.0,
        "Encryption": "aes_256_gcm",
        "EndHiLSN": "0x0",
        "EndLoLSN": "0x22000120",
        "EndTimeline": 1,
        "Keep": false,
        "MajorVersion": 18,
        "MinorVersion": 3,
        "NumberOfTablespaces": 0,
        "RestoreSize": "8.29 MB",
        "Server": "primary",
        "ServerVersion": "0.21.0",
        "StartHiLSN": "0x0",
        "StartLoLSN": "0x22000028",
        "StartTimeline": 1,
        "Tablespaces": {},
        "Valid": 1,
        "WAL": "000000010000000000000022"
    }
}
```

## Using a local LLM

You can also pair **pgmoneta_mcp** with a local LLM runtime for a fully local,
tool-driven assistant workflow.

Add an `[llm]` section to the **client** configuration file (`pgmoneta-mcp-client.conf`):

``` ini
[llm]
provider = ollama
endpoint = http://localhost:11434
model = llama3.1
max_tool_rounds = 10
```

The same `[llm]` section can also be added to the server configuration file
(`pgmoneta-mcp.conf`).

See the **Local LLM** and **Ollama** chapters in the [manual](https://github.com/pgmoneta/pgmoneta/tree/main/doc/manual/en) for the full setup,
including model selection, validation, and configuration details.

## Verifying the Setup

To verify that everything is working correctly:

1. **Check pgmoneta is running**:

``` sh
pgmoneta-cli -c pgmoneta.conf status
```

2. **Check pgmoneta_mcp server logs**:

``` sh
tail -f /tmp/pgmoneta_mcp.log
```

   Look for the `Starting MCP server at` line confirming the server is listening.

## Troubleshooting

### Connection Refused

If you get "Connection refused" errors:

1. Verify pgmoneta is running with management enabled:

``` sh
ps aux | grep pgmoneta
```

2. Check if the management port is listening:

``` sh
netstat -tuln | grep 5000
```

3. Verify firewall settings allow connections to the management port

### Authentication Failed

If authentication fails:

1. Verify the admin user exists in pgmoneta:

``` sh
pgmoneta-admin -f pgmoneta_admins.conf user ls
```

2. Verify the same user exists in pgmoneta_mcp:

``` sh
pgmoneta-mcp-admin -f pgmoneta-mcp-users.conf user ls
```

3. Ensure passwords match between pgmoneta and pgmoneta_mcp

### Master Key Issues

If you get master key errors:

1. Check if master key file exists:

``` sh
ls -la ~/.pgmoneta-mcp/master.key
```

2. Verify permissions (should be 0600):

``` sh
chmod 600 ~/.pgmoneta-mcp/master.key
```

3. Re-copy the pgmoneta master key if needed:

``` sh
mkdir -p ~/.pgmoneta-mcp
cp ~/.pgmoneta/master.key ~/.pgmoneta-mcp/master.key
chmod 600 ~/.pgmoneta-mcp/master.key
```

## Next Steps

Next steps in improving pgmoneta_mcp's configuration could be:

* Read the manual
* Update `pgmoneta-mcp.conf` with the required settings for your system
* Configure logging levels appropriate for your environment
* Set up multiple admin users for team access
* Integrate with your preferred MCP client

See [Configuration][configuration] for more information on these subjects.

## Closing

The [pgmoneta_mcp](https://github.com/pgmoneta/pgmoneta_mcp) community hopes that you find the project interesting.

Feel free to

* [Ask a question](https://github.com/pgmoneta/pgmoneta_mcp/discussions)
* [Raise an issue](https://github.com/pgmoneta/pgmoneta_mcp/issues)
* [Submit a feature request](https://github.com/pgmoneta/pgmoneta_mcp/issues)
* [Write a code submission](https://github.com/pgmoneta/pgmoneta_mcp/pulls)

All contributions are most welcome!

Please, consult our [Code of Conduct](../CODE_OF_CONDUCT.md) policies for interacting in our community.

Consider giving the project a [star](https://github.com/pgmoneta/pgmoneta_mcp/stargazers) on [GitHub](https://github.com/pgmoneta/pgmoneta_mcp/) if you find it useful. And, feel free to follow the project on [X](https://x.com/pgmoneta/) as well.
