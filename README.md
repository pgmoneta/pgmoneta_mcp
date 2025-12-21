# pgmoneta MCP

**pgmoneta MCP** is the official pgmoneta MCP server built for [pgmoneta](https://pgmoneta.github.io/), a backup / restore solution for [PostgreSQL](https://www.postgresql.org). 
For now, this server allows you to query the backup info using natural langue with your MCP client.

## Overview

**pgmoneta MCP** is built upon [rmcp](https://docs.rs/rmcp/latest/rmcp/). It uses [SCRAM-SHA-256](https://datatracker.ietf.org/doc/html/rfc7677) 
to authenticate with pgmoneta server. We also provide an admin tool `pgmoneta_mcp_amdin` to help you manage users.

## Build the project
To build the project, run `cargo build` inside project's root directory. Alternatively, run `cargo install .` to build
and install the project. 

Two binaries `pgmoneta-mcp-server` and `pgmoneta-mcp-admin` will be built.

## License
[GNU General Public License v3.0](https://www.gnu.org/licenses/gpl-3.0.en.html)