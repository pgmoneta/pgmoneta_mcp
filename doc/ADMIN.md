# pgmoneta-mcp-admin user guide

The **pgmoneta-mcp-admin** command line interface manages your users for [**pgmoneta-mcp**](https://github.com/pgmoneta/pgmoneta-mcp).

```
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

Before you add or edit users, copy the pgmoneta master key into the MCP home
directory:

```sh
mkdir -p ~/.pgmoneta-mcp
cp ~/.pgmoneta/master.key ~/.pgmoneta-mcp/master.key
chmod 600 ~/.pgmoneta-mcp/master.key
```

`pgmoneta-mcp-admin` uses `~/.pgmoneta-mcp/master.key` to encrypt passwords in
`pgmoneta-mcp-users.conf`, and the running `pgmoneta-mcp-server` must be able to
read that same file.

## user add

Add a user

Command

```sh
pgmoneta-mcp-admin user add
```

Example

```sh
pgmoneta-mcp-admin -f /etc/pgmoneta-mcp/pgmoneta-mcp-users.conf -U admin user add
```

## user edit

Update a user's password

Command

```sh
pgmoneta-mcp-admin user edit
```

Example

```sh
pgmoneta-mcp-admin -f /etc/pgmoneta-mcp/pgmoneta-mcp-users.conf -U admin user edit
```

## user del

Remove a user

Command

```sh
pgmoneta-mcp-admin user del
```

Example

```sh
pgmoneta-mcp-admin -f /etc/pgmoneta-mcp/pgmoneta-mcp-users.conf -U admin user del
```

## user ls

List all users

Command

```sh
pgmoneta-mcp-admin user ls
```

Example

```sh
pgmoneta-mcp-admin -f /etc/pgmoneta-mcp/pgmoneta-mcp-users.conf user ls
```
