# RPM

This document describes how to build, install, configure and use the RPM package for pgmoneta-mcp.

The RPM packaging files are located in `contrib/rpm/`.

## Prerequisites

You need the following packages installed to build the RPM:

* `rust`
* `cargo`
* `rpm-build`
* `systemd-rpm-macros`

On Fedora / RHEL / CentOS:

```
sudo dnf install rust cargo rpm-build systemd-rpm-macros
```

On Ubuntu / Debian:

```
sudo apt install rustc cargo rpm systemd
```

On Arch Linux:

```
sudo pacman -S rust cargo rpm-tools systemd
```

## Building

1. Prepare the build environment:
   ```
   mkdir -p rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
   ```

2. Update the version in the spec file and create the source tarball:
   ```
   VERSION=$(grep '^version =' Cargo.toml | head -n 1 | cut -d '"' -f 2)
   sed -i "s/^Version:.*/Version:        $VERSION/" contrib/rpm/pgmoneta-mcp.spec

   tar --exclude=rpmbuild --transform "s|^|pgmoneta-mcp-$VERSION/|" -czf rpmbuild/SOURCES/v$VERSION.tar.gz .
   ```

3. Build the RPM:
   ```
   rpmbuild --define "_topdir $(pwd)/rpmbuild" \
            --define "_unitdir /usr/lib/systemd/system" \
            --define "_bindir /usr/bin" \
            --define "_sysconfdir /etc" \
            -bb contrib/rpm/pgmoneta-mcp.spec
   ```

The generated RPMs will be in `rpmbuild/RPMS/`.

## Installation

Install the RPM using `dnf`:

```
sudo dnf install rpmbuild/RPMS/x86_64/pgmoneta-mcp-<version>-1.x86_64.rpm
```

or using `rpm`:

```
sudo rpm -ivh rpmbuild/RPMS/x86_64/pgmoneta-mcp-<version>-1.x86_64.rpm
```

The RPM installs the following:

| Path | Description |
| :--- | :---------- |
| `/usr/bin/pgmoneta-mcp-server` | The MCP server binary |
| `/usr/bin/pgmoneta-mcp-admin` | The admin tool binary |
| `/etc/pgmoneta-mcp/pgmoneta-mcp.conf` | Main configuration file |
| `/etc/pgmoneta-mcp/pgmoneta-mcp-users.conf` | User configuration file |
| `/usr/lib/systemd/system/pgmoneta-mcp.service` | Systemd service unit |
| `/var/log/pgmoneta-mcp/` | Log directory |

A system user and group `pgmoneta` are created automatically during installation.

## Uninstallation

Stop the service first, then remove the package:

```
sudo systemctl stop pgmoneta-mcp
sudo systemctl disable pgmoneta-mcp
sudo dnf remove pgmoneta-mcp
```

or using `rpm`:

```
sudo systemctl stop pgmoneta-mcp
sudo systemctl disable pgmoneta-mcp
sudo rpm -e pgmoneta-mcp
```

Note that configuration files in `/etc/pgmoneta-mcp/` are preserved on removal since they are
marked as `%config(noreplace)`. Remove them manually if no longer needed:

```
sudo rm -rf /etc/pgmoneta-mcp/
sudo rm -rf /var/log/pgmoneta-mcp/
```

## Post-install setup

After installing the RPM, perform the following steps to get pgmoneta-mcp running.

### 1. Copy the master key

The MCP admin tool encrypts user passwords with `~/.pgmoneta-mcp/master.key`.
Copy the pgmoneta master key before creating the MCP users file:

```
mkdir -p ~/.pgmoneta-mcp
cp ~/.pgmoneta/master.key ~/.pgmoneta-mcp/master.key
chmod 600 ~/.pgmoneta-mcp/master.key
```

### 2. Add a user

The RPM ships a placeholder user configuration file. Remove it first so that the admin tool
can create a fresh one with the required `[pgmoneta-mcp-users]` section:

```
sudo rm /etc/pgmoneta-mcp/pgmoneta-mcp-users.conf
```

Then add a user that matches the user configured in your pgmoneta server. The user and password
must match the ones registered with pgmoneta via `pgmoneta-admin`.

```
pgmoneta-mcp-admin user -U <username> -f /etc/pgmoneta-mcp/pgmoneta-mcp-users.conf add -P <password>
```

This creates the user configuration file with the required `[pgmoneta-mcp-users]` section. You can run this
command again to update an existing user's password.

### 3. Configure the server

Edit the main configuration file:

```
sudo vi /etc/pgmoneta-mcp/pgmoneta-mcp.conf
```

The default configuration is:

```
[pgmoneta_mcp]
port = 8000
log_type = file
log_level = info
log_path = /var/log/pgmoneta-mcp/pgmoneta-mcp.log
log_mode = append

[pgmoneta]
host = localhost
port = 5000
metrics = 5001
```

Update the `[pgmoneta]` section to match your pgmoneta instance:

* `host` - The address of the pgmoneta server
* `port` - The management port of the pgmoneta server
* `metrics` - The Prometheus metrics port of the pgmoneta server

See [CONFIGURATION.md](./CONFIGURATION.md) for all available options.

### 4. Verify pgmoneta is running

Make sure the pgmoneta server is up and running in remote admin mode with the management port
configured:

```
pgmoneta -A <your_user_conf.conf> -c <your_pgmoneta_conf.conf>
```

### 5. Start the service

Enable and start pgmoneta-mcp:

```
sudo systemctl enable pgmoneta-mcp
sudo systemctl start pgmoneta-mcp
```

Check the status:

```
sudo systemctl status pgmoneta-mcp
```

Check the logs:

```
sudo journalctl -u pgmoneta-mcp -f
```

or view the log file directly:

```
tail -f /var/log/pgmoneta-mcp/pgmoneta-mcp.log
```
