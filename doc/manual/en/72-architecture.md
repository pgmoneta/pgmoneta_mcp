
# Architecture

## Overview

`pgmoneta-mcp` is an MCP (Model Context Protocol) server that acts as a bridge between AI models and a running
[pgmoneta](https://github.com/pgmoneta/pgmoneta) instance.

```
src/
├── bin/
│   ├── server.rs      ← MCP server entry point
│   └── admin.rs       ← admin CLI (master-key, user add)
├── lib.rs             ← module declarations
├── configuration.rs   ← INI config loading
├── constant.rs        ← command codes, compression, encryption, errors
├── security.rs        ← SCRAM-SHA-256 auth, AES-256-GCM, master key I/O
├── logging.rs         ← tracing/logging setup
├── utils.rs           ← helper utilities
├── handler.rs         ← MCP tool router
├── handler/
│   └── <name>.rs      ← per-tool request structs and handler impls
├── client.rs          ← TCP client: connect, auth, send/receive
└── client/
    └── <name>.rs      ← per-tool wire payload builders
```

The main server entry point is defined in [server.rs](../../../../../../../../../src/bin/server.rs).

The admin CLI tool is defined in [admin.rs](../../../src/bin/admin.rs).

## Configuration

Configuration is handled in [configuration.rs](../../../../../../../../../src/configuration.rs).

A global `OnceCell<Configuration>` singleton is loaded once at startup from two INI files: the main config
(`[pgmoneta_mcp]` + `[pgmoneta]` sections) and the users config (`[admins]` section).

## Security

Security is handled in [security.rs](../../../src/security.rs).

SCRAM-SHA-256 authentication is used when connecting to pgmoneta. Passwords are stored encrypted at rest using
AES-256-GCM. The master key is stored at `~/.pgmoneta-mcp/master.key` with restricted file permissions.

## Handler

The MCP tool router is defined in [handler.rs](../../../src/handler.rs).

Each MCP tool is a function annotated with `#[tool]` inside a `#[tool_router] impl` block on `PgmonetaHandler`.
Tool-specific request structs and their implementations live in [handler/](../../../src/handler/).

## Client

The TCP client is defined in [client.rs](../../../src/client.rs).

The client connects to pgmoneta, performs SCRAM-SHA-256 authentication, and exchanges JSON messages over the wire.
Tool-specific payload structs live in [client/](../../../src/client/).

## The Pattern: 3 Layers Per Tool

Every tool is implemented across exactly three layers:

- **Handler** (`src/handler.rs` + `src/handler/<name>.rs`) — defines the `#[tool]` function, the MCP request struct, and calls the client
- **Client** (`src/client/<name>.rs`) — builds the wire payload and calls `forward_request`
- **Constants** (`src/constant.rs`) — the command code used on the wire

```
AI model
   │  HTTP POST /mcp
   ▼
handler.rs          #[tool] fn → calls handler/<name>.rs
   │
   ▼
handler/<name>.rs   validates args → calls client/<name>.rs
   │
   ▼
client/<name>.rs    builds payload → calls client.rs forward_request
   │
   ▼
client.rs           connect → SCRAM auth → write → read → return JSON
   │
   ▼
pgmoneta
```

## Management

The wire protocol uses JSON over TCP with a small binary framing header (compression byte, encryption byte,
length, JSON body). Remote connections require SCRAM-SHA-256 authentication before the management packet is sent.

The command codes are defined in [constant.rs](../../../src/constant.rs).

## Logging

Logging setup is handled in [logging.rs](../../../src/logging.rs) using the `tracing` crate.
