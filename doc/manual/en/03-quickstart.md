\newpage

# Quick start

Make sure that [**pgmoneta_mcp**][pgmoneta_mcp] is installed and in your path by using `pgmoneta-mcp-server --help`. You should see

``` console
pgmoneta-mcp-server 0.2.1
  MCP server for pgmoneta

Usage:
  pgmoneta-mcp-server [OPTIONS]

Options:
  -c, --config <CONFIG>  Path to configuration file [default: /etc/pgmoneta-mcp/pgmoneta-mcp.conf]
  -u, --users <USERS>    Path to users file [default: /etc/pgmoneta-mcp/pgmoneta-mcp-users.conf]
  -h, --help             Print help
  -V, --version          Print version
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

You will be prompted for the password. Alternatively, use the `-P` flag or `PGMONETA_PASSWORD` environment variable:

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
- `log_type`: Logging destination - `file`, `console`, or `syslog`
- `log_level`: Log level - `trace`, `debug`, `info`, `warn`, or `error`
- `log_path`: Path to log file (when `log_type = file`)
- `[pgmoneta]` section:
  - `host`: Hostname where pgmoneta server is running
  - `port`: Management port of pgmoneta server (must match pgmoneta's `management` setting)

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
pgmoneta-mcp-admin 0.2.1
  Administration utility for pgmoneta_mcp

Usage:
  pgmoneta-mcp-admin [OPTIONS] <COMMAND>

Commands:
  user        Manage users
  help        Print this message or the help of the given subcommand(s)

Options:
  -f, --file <FILE>          Path to users file
  -U, --user <USER>          Username
  -P, --password <PASSWORD>  Password
  -g, --generate             Generate a password
  -l, --length <LENGTH>      Password length [default: 64]
  -F, --format <FORMAT>      Output format (text or json) [default: text]
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

**Add a user with generated password**:

``` sh
pgmoneta-mcp-admin -f pgmoneta-mcp-users.conf -U admin -g user add
```

**List all users**:

``` sh
pgmoneta-mcp-admin -f pgmoneta-mcp-users.conf user ls
```

**List users in JSON format**:

``` sh
pgmoneta-mcp-admin -f pgmoneta-mcp-users.conf -F json user ls
```

**Edit a user's password**:

``` sh
pgmoneta-mcp-admin -f pgmoneta-mcp-users.conf -U admin user edit
```

**Delete a user**:

``` sh
pgmoneta-mcp-admin -f pgmoneta-mcp-users.conf -U admin user del
```

## Connecting MCP Clients

### VS Code with GitHub Copilot

**Prerequisites**:
- VS Code installed
- GitHub Copilot extension installed

**Add the server**:

1. Open the Command Palette in VS Code (F1 or Ctrl+Shift+P)
2. Type "MCP: Add Server"
3. Configure your server with the following settings:
   - Name: `pgmoneta`
   - URL: `http://localhost:8000/mcp` (adjust host/port as needed)

**Start the server**:

1. Go to the Extensions tab
2. Find your pgmoneta MCP server
3. Click the gear icon
4. Choose "Start Server"

**Use the server**:

Open a chat (Ctrl + Alt + I) and try:
- "Say hello to the pgmoneta MCP server"
- "Get information about the latest backup for server primary"
- "List all backups for server primary"

### Claude Desktop

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

## Using a local LLM

You can also pair **pgmoneta_mcp** with a local LLM runtime for a fully local,
tool-driven assistant workflow.

Add an `[llm]` section to `pgmoneta-mcp.conf`:

``` ini
[llm]
provider = ollama
endpoint = http://localhost:11434
model = llama3.1
max_tool_rounds = 10
```

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

3. **Test MCP connection** (from your MCP client):
   - Ask: "Say hello to the pgmoneta MCP server"
   - Expected response: "Hello from pgmoneta MCP server!"

4. **Test backup query** (from your MCP client):
   - Ask: "Get information about the latest backup for server primary"
   - Expected: Detailed backup information in JSON format

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
