Name:           pgmoneta-mcp
Version:        0.2.1
Release:        1%{?dist}
Summary:        MCP server for pgmoneta
License:        GPLv3+
URL:            https://github.com/pgmoneta/pgmoneta_mcp
Source0:        https://github.com/pgmoneta/pgmoneta_mcp/archive/v%{version}.tar.gz

BuildRequires:  rust
BuildRequires:  cargo
BuildRequires:  systemd-rpm-macros

Requires:       systemd
Requires(pre):  shadow-utils
Provides:       group(pgmoneta)
Provides:       user(pgmoneta)

%description
pgmoneta MCP is the official pgmoneta MCP server built for pgmoneta,
a backup / restore solution for PostgreSQL.

%prep
%setup -q

%build
cargo build --release

%install
rm -rf %{buildroot}
install -D -m 0755 target/release/pgmoneta-mcp-server %{buildroot}%{_bindir}/pgmoneta-mcp-server
install -D -m 0755 target/release/pgmoneta-mcp-admin %{buildroot}%{_bindir}/pgmoneta-mcp-admin
install -D -m 0644 contrib/rpm/pgmoneta-mcp.conf %{buildroot}%{_sysconfdir}/pgmoneta-mcp/pgmoneta-mcp.conf
install -D -m 0644 contrib/rpm/pgmoneta-mcp-users.conf %{buildroot}%{_sysconfdir}/pgmoneta-mcp/pgmoneta-mcp-users.conf
install -D -m 0644 contrib/rpm/pgmoneta-mcp.service %{buildroot}%{_unitdir}/pgmoneta-mcp.service
install -d -m 0755 %{buildroot}/var/log/pgmoneta-mcp

%pre
getent group pgmoneta >/dev/null || groupadd -r pgmoneta
getent passwd pgmoneta >/dev/null || \
    useradd -r -g pgmoneta -d /home/pgmoneta -s /sbin/nologin \
    -c "pgmoneta user" pgmoneta
exit 0

%post
%systemd_post pgmoneta-mcp.service

%preun
%systemd_preun pgmoneta-mcp.service

%postun
%systemd_postun_with_restart pgmoneta-mcp.service

%files
%license LICENSE
%doc README.md
%{_bindir}/pgmoneta-mcp-server
%{_bindir}/pgmoneta-mcp-admin
%dir %{_sysconfdir}/pgmoneta-mcp
%config(noreplace) %attr(0640, pgmoneta, pgmoneta) %{_sysconfdir}/pgmoneta-mcp/pgmoneta-mcp.conf
%config(noreplace) %attr(0640, pgmoneta, pgmoneta) %{_sysconfdir}/pgmoneta-mcp/pgmoneta-mcp-users.conf
%{_unitdir}/pgmoneta-mcp.service
%dir %attr(0750, pgmoneta, pgmoneta) /var/log/pgmoneta-mcp

%changelog
* Sat Feb 08 2025 pgmoneta-mcp developers <pgmoneta-mcp@pgmoneta.org> - 0.2.0-1
- Initial release
