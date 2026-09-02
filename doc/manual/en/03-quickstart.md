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

Initialize `orangu-server`, download the model recommended by the latest
Orangu getting-started guide, and start its OpenAI API:

``` sh
orangu-server -i
orangu-server download ggml-org/gemma-4-E4B-it-GGUF
orangu-server --all ggml-org/gemma-4-E4B-it-GGUF
```

Keep `orangu-server` running in that terminal.

Create a client configuration file called `pgmoneta-mcp-client.conf`:

``` ini
[pgmoneta_mcp_client]
url = http://localhost:6432/mcp
timeout = 30
model = gemma

[gemma]
provider = openai
endpoint = http://localhost:8100/v1
model = ggml-org/gemma-4-E4B-it-GGUF
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

```
Successfully created a full backup on **primary**.

### Backup Summary

*   **Server:** primary
*   **Server Version:** 0.22.0
*   **Backup ID:** 20260726043310
*   **Backup Type:** Full (Incremental: No)
*   **Status:** Success

### Operation Details

*   **Operation Status:** True
*   **Overall Success:** True
*   **Time Taken:** Completed in about 2 seconds
*   **Compression:** zstd
*   **Encryption:** aes_256_gcm
*   **Major Version:** 18
*   **Minor Version:** 1
*   **Valid:** 1

### File Information

*   **Backup Size:** 3.77 MB
*   **Restore Size:** 6.20 MB
*   **Biggest File Size:** 232.00 KB
*   **Incremental Parent:** (None)
```

A new backup is created. You can use this label in the
next step, or simply use `latest` to refer to the newest backup.

## List backups

Ask:

``` text
List backups for server primary in descending order
```

Example Output:

```
Listed the backups for the primary server in descending order, which was completed in about 0 seconds.

### Server Backup Details
*   **Server Name:** primary
*   **Server Version:** 0.22.0
*   **Total Number of Backups:** 10
*   **Major Version:** 18
*   **Minor Version:** 1

### Backup History (Descending Order)

Here is the detailed list of the 10 backups found on the primary server.

| Backup ID | Backup Size | Biggest File Size | Incremental | Parent ID | Keep | Restore Size |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **20260726043310** | 6.20 MB | 232.00 KB | No | - | No | 6.20 MB |
| 20260726012918 | 3.78 MB | 3.35 MB | Yes | 20260726011802 | No | 25.37 MB |
| 20260726011802 | 3.77 MB | 232.00 KB | No | - | No | 6.20 MB |
| 20260726011743 | 3.77 MB | 232.00 KB | No | - | No | 6.20 MB |
| 20260726011419 | 3.77 MB | 232.00 KB | No | - | No | 6.20 MB |
| 20260726010308 | 3.77 MB | 232.00 KB | No | - | No | 6.20 MB |
| 20260726005422 | 3.77 MB | 232.00 KB | No | - | No | 6.20 MB |
| 20260726004442 | 3.77 MB | 232.00 KB | No | - | No | 6.20 MB |
| 20260726004007 | 3.77 MB | 232.00 KB | No | - | No | 6.20 MB |
| 20260726003033 | 6.20 MB | 232.00 KB | No | - | No | 6.20 MB |

***

**Common Backup Details:**
*   **Compression:** zstd
*   **Encryption:** aes\_256\_gcm
*   **Valid:** All backups are valid (1).
*   **WAL (Write Ahead Log):** 0 (All backups).
```

## Restore a backup

Choose one backup from the list, or use `latest`, and restore it into an empty
target directory on the pgmoneta host.

Ask:

``` text
Restore the latest backup for server primary to /tmp/restore
```

Example Output:

```
Restored the latest backup for the primary server into /tmp/restore.

**Restore Summary:**

*   **Success:** True
*   **Time Taken:** Completed in about 14 seconds
*   **Server:** primary
*   **Server Version:** 0.22.0
*   **Backup ID:** **20260726043310**
*   **Backup Size:** 6.20 MB
*   **Restore Size:** 6.20 MB
*   **Biggest File Size:** 232.00 KB
*   **Incremental:** No
*   **Compression:** zstd
*   **Encryption:** aes_256_gcm
*   **Major Version:** 18
*   **Minor Version:** 1
*   **Comments:**
```

The restore should complete successfully:

- The command reports success
- The restore target directory contains restored database files

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

Example Output:

```
Retrieved detailed information for the latest backup on the primary server.

### **Backup Summary**

*   **Backup ID:** 20260726023426
*   **Server Name:** primary
*   **Server Version:** 0.22.0
*   **Comments:** ticket|before release
*   **Backup Status:** **Valid**
*   **Compression:** zstd
*   **Encryption:** aes\_256\_gcm
*   **Keep:** No

### **Size and Storage Details**

*   **Backup Size:** 3.78 MB
*   **Restore Size:** 25.37 MB
*   **Biggest File Size:** 3.35 MB
*   **WAL File:** 000000010000000300000082

### **Time and Versioning**

*   **Elapsed Time:** Completed in less than 1 second (0.0 seconds)
*   **Major Version:** 18
*   **Minor Version:** 1
*   **Tablespaces:** 0

### **LSN and Timeline Details**

**Start Details:**
*   **Start LSN:** 0x82000028
*   **Start HiLSN:** 0x3
*   **Start Timeline:** 1

**End Details:**
*   **End LSN:** 0x82000120
*   **End HiLSN:** 0x3
*   **End Timeline:** 1

**Checkpoint Details:**
*   **Checkpoint LoLSN:** 0x82000080
*   **Checkpoint HiLSN:** 0x3
```

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
