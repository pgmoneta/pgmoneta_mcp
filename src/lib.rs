// Copyright (C) 2026 The pgmoneta community
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! # pgmoneta-mcp
//!
//! A Model Context Protocol (MCP) server for [pgmoneta](https://pgmoneta.github.io/),
//! providing AI assistants with the capability to interact with PostgreSQL backups.
//!
//! This library provides the core components for the MCP server:
//! * **`configuration`**: Parses and stores application and user settings.
//! * **`constant`**: Defines standard codes, commands, and formatting rules.
//! * **`client`**: Manages low-level TCP communication with the pgmoneta server.
//! * **`handler`**: Implements the MCP protocol and routes tool calls.
//! * **`compression`**: Handles data compression and decompression.
//! * **`security`**: Handles master key management, AES encryption, and SCRAM authentication.
//! * **`utils`**: Provides shared helper functions.

pub mod agent;
pub mod compression;
pub mod configuration;
pub mod constant;
pub mod handler;
pub mod llm;

mod client;
pub mod logging;
pub mod mcp_client;
pub mod security;
pub mod utils;
