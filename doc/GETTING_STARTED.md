# Getting Started

## Prerequisites

You need to have PostgreSQL 14+ and pgmoneta installed and running. See pgmoneta's
[manual](https://github.com/pgmoneta/pgmoneta/tree/main/doc/manual/en) on how to install and run pgmoneta. Note that
you need to run pgmoneta in remote admin mode, with yourself added to the users configuration. You also need to configure
`management` in your configuration to specify the port the pgmoneta server runs management at.

First, add yourself to users if you haven't done that already.

```
pgmoneta-admin -U <your_user_id> -P <your_password> -f <your_user_conf_file> user add
```

Second, run pgmoneta in remote admin mode with management port configured.

```
pgmoneta -A <your_user_conf.conf> -c <your_pgmoneta_conf.conf>
```

## Build the project

To build the project, run `cargo build` inside project's root directory. This will build two binaries, `pgmoneta-mcp-server`
and `pgmoneta-mcp-admin`. Alternatively, run `cargo install .` to build and install the project.

## Configure user

First, add the master key if you haven't done that already.

```
pgmoneta-mcp-admin master-key
```

This will prompt you to input your master key.

Add the same user and password you added to pgmoneta server to pgmoneta MCP server, creating or updating
your user configuration file.

```
pgmoneta-mcp-admin user -U <your_user_id> -P <your_password> -f <your_mcp_user_conf.conf> add
```

## Configure pgmoneta MCP server

Create a configuration file `pgmoneta_mcp.conf`. An example is as follows

```
[pgmoneta_mcp]
port = 8000

[pgmoneta]
host = "localhost"
port = 5000
```

Note that the port under pgmoneta section has to match your management port configured earlier. While the first port
is what you'll run your MCP server at.

## Run MCP server

First check again if your pgmoneta server is up and running. Then to start the server, run

```
pgmoneta-mcp-server -c pgmoneta_mcp.conf -u pgmoneta_mcp_users.conf
```

The defaults for configuration is `/etc/pgmoneta-mcp/pgmoneta-mcp.conf` and for users it is
`/etc/pgmoneta-mcp/pgmoneta-mcp-users.conf`.

## Add MCP server to VS Code

We will use VS code as an example. You can of course choose other MCP clients.

**Prerequisite**

You need to have GitHub Copilot extension installed in VS code.

**Add your server**

Open the Command Palette in VS Code (F1), type "MCP: Add Server" to configure your server in VS Code.

Note that if your server is running remotely, you may need to configure firewall and/or network inbound rules
to open the corresponding port, or alternatively, use SSH tunneling.

**Start your server**

At the extension tab, you will see the installed MCP servers. Choose the pgmoneta MCP server you just added,
click the gear icon, choose "Start Server". This will let VS Code to try connecting with your MCP server and
discover available tool.

**Use your MCP server**

Open a chat (shortcut: Ctrl + Alt + I). Try asking your model to ask the server to say hello, or query
your latest backup info!

## Closing

The [pgmoneta-mcp](https://github.com/pgmoneta/pgmoneta_mcp) community hopes that you find
the project interesting.

Feel free to

* [Ask a question](https://github.com/pgmoneta/pgmoneta_mcp/discussions)
* [Raise an issue](https://github.com/pgmoneta/pgmoneta_mcp/issues)
* [Submit a feature request](https://github.com/pgmoneta/pgmoneta_mcp/issues)
* [Write a code submission](https://github.com/pgmoneta/pgmoneta_mcp/pulls)

All contributions are most welcome !

Please, consult our [Code of Conduct](../CODE_OF_CONDUCT.md) policies for interacting in our
community.

Consider giving the project a [star](https://github.com/pgmoneta/pgmoneta_mcp/stargazers) on
[GitHub](https://github.com/pgmoneta/pgmoneta_mcp/) if you find it useful. And, feel free to follow
the project on [X](https://x.com/pgmoneta/) as well.
