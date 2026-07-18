\newpage

# Quick start

This chapter walks through a complete first pgmoneta_mcp flow:

1. Set up pgmoneta with remote administration enabled
2. Configure and start pgmoneta_mcp
3. Connect with the native `pgmoneta-mcp-client`
4. Take a backup, list backups, and restore a backup

Make sure that [**pgmoneta_mcp**][pgmoneta_mcp] is installed and in your path by
using `pgmoneta-mcp-server --help`. You should see:

``` console
A Model Context Protocol (MCP) server for pgmoneta, backup/restore tool for PostgreSQL

Usage: pgmoneta-mcp-server [OPTIONS]

Options:
  -c, --conf <CONF>    Path to pgmoneta MCP configuration file [default: /etc/pgmoneta-mcp/pgmoneta-mcp.conf]
  -u, --users <USERS>  Path to pgmoneta MCP users configuration file [default: /etc/pgmoneta-mcp/pgmoneta-mcp-users.conf]
  -h, --help           Print help
```

If you encounter any issues following the above steps, refer to the
**Installation** chapter to see how to install or compile pgmoneta_mcp on your
system.

## Set up pgmoneta

You need PostgreSQL 14+ and pgmoneta installed and running. See pgmoneta's
[manual](https://github.com/pgmoneta/pgmoneta/tree/main/doc/manual/en) for how
to install and run pgmoneta.

**Important**: You need to run pgmoneta in remote admin mode with management
enabled. This allows pgmoneta_mcp to communicate with the pgmoneta server.

In your pgmoneta configuration (`pgmoneta.conf`), ensure you have:

``` ini
[pgmoneta]
management = 5000
```

Start pgmoneta with the admins file:

``` sh
pgmoneta -A pgmoneta_admins.conf -c pgmoneta.conf -u pgmoneta_users.conf
```

## Set up pgmoneta_mcp

The MCP server needs a master key, a user file, and a server configuration file.

**Master Key**

First, copy the pgmoneta master key into the MCP home directory. This key is
used to encrypt admin passwords stored in the MCP user configuration file.

``` sh
mkdir -p ~/.pgmoneta-mcp
cp ~/.pgmoneta/master.key ~/.pgmoneta-mcp/master.key
chmod 600 ~/.pgmoneta-mcp/master.key
```

Do this before creating or updating `pgmoneta-mcp-users.conf`. The running
`pgmoneta-mcp-server` process must use the same
`~/.pgmoneta-mcp/master.key` that was used when this users file was created or
updated.

**User Configuration**

Add an admin user to pgmoneta_mcp. This should be the same user you configured
in pgmoneta's admins file.

``` sh
pgmoneta-mcp-admin -f pgmoneta-mcp-users.conf -U admin user add
```

You will be prompted for the password. Alternatively, use the `-P` flag or the
`PGMONETA_PASSWORD` environment variable:

``` sh
pgmoneta-mcp-admin -f pgmoneta-mcp-users.conf -U admin -P secretpassword user add
```

The password will be encrypted using the master key and stored in
`pgmoneta-mcp-users.conf`.

If the server runs under a different OS user or `HOME`, copy the same key into
that user's `~/.pgmoneta-mcp/master.key` before starting the server, otherwise
password decryption will fail when executing tools.

**Server Configuration**

Create a configuration file called `pgmoneta-mcp.conf` with the following
content:

``` ini
[pgmoneta_mcp]
port = 8000
log_type = file
log_level = info
log_path = /tmp/pgmoneta_mcp.log

[pgmoneta]
host = localhost
port = 5000
metrics = 5001
```

**Configuration options**:

- `port`: Port where the MCP server will listen (default: 8000)
- `log_type`: Logging destination - `file`, `console`, or `syslog`
- `log_level`: Log level - `trace`, `debug`, `info`, `warn`, or `error`
- `log_path`: Path to log file (when `log_type = file`)
- `[pgmoneta]` section:
  - `host`: Hostname where pgmoneta server is running
  - `port`: Management port of pgmoneta server (must match pgmoneta's `management` setting)
  - `metrics`: Prometheus metrics port of pgmoneta server (defaults to `5001`)

See the **Configuration** chapter for all configuration options.

Start the MCP server:

``` sh
pgmoneta-mcp-server -c pgmoneta-mcp.conf -u pgmoneta-mcp-users.conf
```

If this does not give an error, the MCP server is running and ready to accept
connections.

The server can be stopped by pressing Ctrl-C (`^C`) in the console where you
started it, or by sending the `SIGTERM` signal to the process using
`kill <pid>`.

## Set up the native client

The quickest way to try pgmoneta_mcp is the native terminal client,
`pgmoneta-mcp-client`. It connects to the MCP server, injects the selected
username automatically, and can run both natural-language requests and direct
tool calls.

Create a client configuration file called `pgmoneta-mcp-client.conf`:

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

Start the client:

``` sh
pgmoneta-mcp-client -c pgmoneta-mcp-client.conf -u pgmoneta-mcp-users.conf
```

After startup, the client is in user mode by default. User mode uses the
configured client LLM profile, so make sure the profile endpoint is running if
you want natural-language execution. You can ask for outcomes in natural
language, for example:

``` text
Take a backup for server primary
List backups for server primary in descending order
Restore the latest backup for server primary to /tmp/pgmoneta-restore
```

You can also switch to developer mode and call tools with JSON arguments. This
is useful when you want to test the MCP tools directly:

``` text
/developer
backup {"server":"primary"}
list_backups {"server":"primary","sort":"desc"}
restore {"server":"primary","backup_id":"latest","directory":"/tmp/pgmoneta-restore"}
```

See the **Client** chapter for more native client usage and third-party MCP
client examples.

## Take a backup

In `pgmoneta-mcp-client`, ask:

``` text
Take a backup for server primary
```

Example Output:

``` text
primary (pgmoneta 0.22.0 w/ PostgreSQL 18.1)
* 20260706113507 | Full, Backup: 6.03 MB, Restore: 6.02 MB, Valid
```

A new backup label `20260706113507` is created. You can use this label in the
next step, or simply use `latest` to refer to the newest backup.

## List backups

Ask:

``` text
List backups for server primary in descending order
```

Example Output:

``` text
{
    "Header": {
        "ClientVersion": "0.21.0",
        "Command": "list-backup",
        "Compression": "zstd",
        "Encryption": "aes_256_gcm",
        "Output": 1,
        "Timestamp": 20260714124309
    },
    "Outcome": {
        "Status": true,
        "Time": "00:00:0.0023"
    },
    "Request": {
        "Server": "primary",
        "Sort": "desc"
    },
    "Response": {
        "Backups": [
            {
                "Backup": 20260712211454,
                "BackupSize": "6.11 MB",
                "BiggestFileSize": "232.00 KB",
                "Comments": "",
                "Compression": "zstd",
                "Encryption": "aes_256_gcm",
                "Incremental": false,
                "IncrementalParent": "",
                "Keep": false,
                "RestoreSize": "6.10 MB",
                "Server": "primary",
                "Valid": 1,
                "WAL": 0
            }
        ],
        "MajorVersion": 0,
        "MinorVersion": 0,
        "NumberOfBackups": 1,
        "Server": "primary",
        "ServerVersion": "0.22.0"
    }
}
```

## Restore a backup

Choose one backup from the list, or use `latest`, and restore it into an empty
target directory on the pgmoneta host.

Ask:

``` text
Restore the latest backup for server primary to /tmp/pgmoneta-restore
```

Example Output:

- The command returns success `true` in `Outcome.Status`
- The restore target directory contains restored database files

Example:

``` text
{
    "Header": {
        "ClientVersion": "0.21.0",
        "Command": "restore",
        "Compression": "zstd",
        "Encryption": "aes_256_gcm",
        "Output": 1,
        "Timestamp": 20260714124440
    },
    "Outcome": {
        "Status": true,
        "Time": "00:00:4.3680"
    },
    "Request": {
        "Backup": "latest",
        "Directory": "/tmp/pgmoneta-restore",
        "Position": "current",
        "Server": "primary"
    },
    "Response": {
        "Backup": 20260712211454,
        "BackupSize": "6.11 MB",
        "BiggestFileSize": "232.00 KB",
        "Comments": "",
        "Compression": "zstd",
        "Encryption": "aes_256_gcm",
        "Incremental": false,
        "IncrementalParent": "",
        "MajorVersion": 0,
        "MinorVersion": 0,
        "RestoreSize": "6.10 MB",
        "Server": "primary",
        "ServerVersion": "0.22.0"
    }
}
```

If something fails, check the **Troubleshooting** section below and inspect MCP
server logs.

## Administration reference

[**pgmoneta_mcp**][pgmoneta_mcp] has an administration tool called
`pgmoneta-mcp-admin`, which is used to manage user accounts.

You can see the commands it supports by using `pgmoneta-mcp-admin --help`,
which will give:

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
```

**Master Key Preparation**

Before using `pgmoneta-mcp-admin user ...`, copy the pgmoneta master key into
the MCP home directory:

``` sh
mkdir -p ~/.pgmoneta-mcp
cp ~/.pgmoneta/master.key ~/.pgmoneta-mcp/master.key
chmod 600 ~/.pgmoneta-mcp/master.key
```

**User Management**

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

## Using a local LLM

You can pair the **pgmoneta_mcp** native client with a local LLM runtime for a fully local (needed for the `/user` language interaction),
tool-driven assistant workflow.

Add an `[llm]` section to `pgmoneta-mcp-client.conf`:

``` ini
[llm]
provider = ollama
endpoint = http://localhost:11434
model = llama3.1
max_tool_rounds = 10
```
and set the **model** (under the **pgmoneta_mcp_client** section) to the name of the llm section.

```ini
[pgmoneta_mcp_client]
url = http://localhost:6432/mcp
timeout = 30
model = gemma

[qwen]
provider = ollama
endpoint = http://localhost:11434
model = qwen2.5:3b
max_tool_rounds = 10

[gemma]
provider = llama.cpp
endpoint = http://localhost:8100/v1
model = ggml-org/gemma-4-E4B-it-GGUF
```

See the **Local LLM** and **Ollama** chapters in the
[manual](https://github.com/pgmoneta/pgmoneta_mcp/tree/main/doc/manual/en) for the
full setup, including model selection, validation, and configuration details.

## Verifying the setup

To verify that everything is working correctly:

1. **Check pgmoneta is running**:

``` sh
pgmoneta-cli -c pgmoneta.conf status
```

2. **Check pgmoneta_mcp server logs**:

``` sh
tail -f /tmp/pgmoneta_mcp.log
```

3. **Test MCP connection** in `pgmoneta-mcp-client`:

``` text
Say hello to the pgmoneta MCP server
```

Expected response:

``` text
Hello from pgmoneta MCP server!
```

4. **Test backup query** in `pgmoneta-mcp-client`:

``` text
Get information about the latest backup for server primary
```

Example Output: detailed backup information in JSON format.

## Troubleshooting

**Connection Refused**

If you get "Connection refused" errors:

1. Verify pgmoneta is running with management enabled:

``` sh
ps aux | grep pgmoneta
```

2. Check if the management port is listening:

``` sh
netstat -tuln | grep 5000
```

3. Verify firewall settings allow connections to the management port.

**Authentication Failed**

If authentication fails:

1. Verify the admin user exists in pgmoneta:

``` sh
pgmoneta-admin -f pgmoneta_admins.conf user ls
```

2. Verify the same user exists in pgmoneta_mcp:

``` sh
pgmoneta-mcp-admin -f pgmoneta-mcp-users.conf user ls
```

3. Ensure passwords match between pgmoneta and pgmoneta_mcp.

**Master Key Issues**

If you get master key errors:

1. Check if the master key file exists:

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

The [pgmoneta_mcp](https://github.com/pgmoneta/pgmoneta_mcp) community hopes
that you find the project interesting.

Feel free to

* [Ask a question](https://github.com/pgmoneta/pgmoneta_mcp/discussions)
* [Raise an issue](https://github.com/pgmoneta/pgmoneta_mcp/issues)
* [Submit a feature request](https://github.com/pgmoneta/pgmoneta_mcp/issues)
* [Write a code submission](https://github.com/pgmoneta/pgmoneta_mcp/pulls)

All contributions are most welcome!

Please, consult our [Code of Conduct](../CODE_OF_CONDUCT.md) policies for
interacting in our community.

Consider giving the project a
[star](https://github.com/pgmoneta/pgmoneta_mcp) on
[GitHub](https://github.com/pgmoneta/pgmoneta_mcp) if you find it useful. And,
feel free to follow the project on [X](https://x.com/pgmoneta/) as well.
