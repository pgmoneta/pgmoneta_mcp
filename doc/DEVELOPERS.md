# Developer Guide

This document describes the development workflow for **pgmoneta_mcp**.

It is intended for developers who want to build, test, debug, or extend the project.

- For contribution rules and PR workflow, see [CONTRIBUTING.md](../CONTRIBUTING.md)
- For user setup and runtime configuration, see [GETTING_STARTED.md](GETTING_STARTED.md)

---

## Prerequisites

- Rust 1.85+
- Rust toolchain (stable), preferably installed via [rustup](https://rustup.rs)
- `cargo` (included with Rust)
- `git`
- A running **pgmoneta** instance for integration testing

On Linux, some distributions provide useful system packages:

```bash
# Fedora / RHEL
sudo dnf install git rustfmt clippy

# Debian / Ubuntu
sudo apt-get install git cargo rustfmt clippy
```

Using **rustup** is recommended for consistent toolchain management across platforms.

---

## Building

All build tasks are handled by Cargo.

### Debug build

```bash
cargo build
```

### Release build

```bash
cargo build --release
```

Binaries are placed in:

* `target/debug/`
* `target/release/`

---

## Formatting and Linting

Code formatting and linting are enforced by CI.

### Format code

```bash
cargo fmt --all
```

### Check formatting (CI mode)

```bash
cargo fmt --all --check
```

### Run Clippy

```bash
cargo clippy
```

### Clippy with warnings as errors (CI)

```bash
cargo clippy -- -D warnings
```

All Clippy warnings must be resolved before submitting a pull request.

---

## Testing

### Run all tests

```bash
cargo test
```

### Run tests with output

```bash
cargo test -- --nocapture
```

### Run tests matching a pattern

```bash
cargo test <pattern>
```

---

## Running and Debugging

### Run server during development

```bash
cargo run --bin pgmoneta-mcp-server -- -c pgmoneta-mcp.conf -u pgmoneta-mcp-users.conf
```

### Run built binaries directly

```bash
./target/debug/pgmoneta-mcp-server -c <config> -u <users>
./target/debug/pgmoneta-mcp-admin --help
```

### Debugging

Rust debugging can be done using:

```bash
rust-lldb target/debug/pgmoneta-mcp-server
# or
rust-gdb target/debug/pgmoneta-mcp-server
```

VS Code users can debug using the **CodeLLDB** extension.

---

## Logging

The project uses the `tracing` ecosystem for logging.

Logging is primarily configured via the configuration file.  

---

## Adding a New Tool

The MCP server uses [rmcp](https://crates.io/crates/rmcp) v1's **trait-based tool system**. Each tool is a self-contained struct that defines its own name, description, parameters, and handler logic. Tools live in separate files under `src/handler/`.

### Architecture

```
src/handler.rs              ← Router + shared helpers (parse, translate, serialize)
src/handler/hello.rs        ← SayHelloTool (SyncTool)
src/handler/info.rs         ← GetBackupInfoTool, ListBackupsTool (AsyncTool)
src/handler/<new_tool>.rs   ← Your new tool goes here
```

`handler.rs` only needs two changes when adding a tool:
1. `mod new_tool;` — declare the submodule
2. `.with_async_tool::<new_tool::MyTool>()` — register it in the router

Everything else (name, description, parameters, logic, tests) lives in the tool's own file.

### Step-by-step

#### 1. Create the tool file

Create `src/handler/my_command.rs`:

```rust
use std::borrow::Cow;
use std::sync::Arc;

use super::PgmonetaHandler;
use crate::client::PgmonetaClient;
use rmcp::ErrorData as McpError;
use rmcp::handler::server::router::tool::{AsyncTool, ToolBase};
use rmcp::model::JsonObject;
use rmcp::schemars;

// Define the parameter struct with required derives
#[derive(Debug, Default, serde::Deserialize, schemars::JsonSchema)]
pub struct MyCommandRequest {
    pub username: String,
    pub server: String,
}

// Define the tool struct
pub struct MyCommandTool;

impl ToolBase for MyCommandTool {
    type Parameter = MyCommandRequest;
    type Output = String;
    type Error = McpError;

    fn name() -> Cow<'static, str> {
        "my_command".into()
    }

    fn description() -> Option<Cow<'static, str>> {
        Some("Description of what this tool does".into())
    }

    // input_schema is NOT overridden — the default generates the correct JSON schema
    // automatically from `type Parameter` via its JsonSchema derive.

    // output_schema must be overridden to return None because our Output type is String
    // (dynamically-translated JSON), and the MCP spec requires output schema root type
    // to be 'object', which String does not satisfy.
    fn output_schema() -> Option<Arc<JsonObject>> {
        None
    }
}

impl AsyncTool<PgmonetaHandler> for MyCommandTool {
    async fn invoke(
        _service: &PgmonetaHandler,
        request: MyCommandRequest,
    ) -> Result<String, McpError> {
        // Call pgmoneta via the client
        let result: String = PgmonetaClient::request_my_command(
            &request.username,
            &request.server,
        )
        .await
        .map_err(|e| {
            McpError::internal_error(
                format!("Failed to execute my_command: {:?}", e),
                None,
            )
        })?;

        // Use the shared pipeline to parse and translate the response
        PgmonetaHandler::generate_call_tool_result_string(&result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp::handler::server::router::tool::ToolBase;

    #[test]
    fn test_my_command_tool_metadata() {
        assert_eq!(MyCommandTool::name(), "my_command");
        assert!(MyCommandTool::description().is_some());
    }
}
```

#### 2. Register the tool

In `src/handler.rs`, add the module declaration and register the tool:

```rust
mod hello;
mod info;
mod my_command;  // ← add this

// ...

pub fn tool_router() -> ToolRouter<Self> {
    ToolRouter::new()
        .with_sync_tool::<hello::SayHelloTool>()
        .with_async_tool::<info::GetBackupInfoTool>()
        .with_async_tool::<info::ListBackupsTool>()
        .with_async_tool::<my_command::MyCommandTool>()  // ← add this
}
```

#### 3. Run checks

```bash
cargo fmt
cargo build
cargo test
```

### Key traits

| Trait | Use when |
|-------|----------|
| `SyncTool<PgmonetaHandler>` | No async operations needed (e.g., `SayHelloTool`) |
| `AsyncTool<PgmonetaHandler>` | Tool calls pgmoneta or does I/O (most tools) |

### Shared response pipeline

For tools that call pgmoneta, use `PgmonetaHandler::generate_call_tool_result_string(&raw_json)`. This method:
1. Parses the raw JSON response
2. Validates the `Outcome` field is present
3. Translates numeric fields to human-readable formats (file sizes, LSNs, compression/encryption names)
4. Returns the translated JSON as a `String`

### Required derives for parameter structs

Parameter structs must derive:
- `Debug` — for error messages
- `Default` — required by `ToolBase::Parameter` bound
- `serde::Deserialize` — for JSON deserialization
- `schemars::JsonSchema` — for auto-generated JSON schema

---

## Continuous Integration

The project uses GitHub Actions for CI. The pipeline includes:

- **Formatting**: Ensures code adheres to style guidelines using `cargo fmt`.
- **Linting**: Checks for common issues using `clippy`.
- **Build Validation**: Verifies the code compiles using `cargo check`.

To run these checks locally:

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features
cargo check
```

---

## License Headers

This project uses [`licensesnip`](https://github.com/notken12/licensesnip) to ensure source files include correct license headers.

If you haven't already installed licensesnip, you can do so using Cargo:

```bash
cargo install licensesnip
```

When adding new source files, run `licensesnip` from the project root:

```bash
licensesnip
```

The license template is defined in `.licensesnip`. Running `licensesnip` will automatically insert the correct header where needed.

---

## Contributing Notes

* Add yourself to the `AUTHORS` file in your first pull request
* When committing, use the format `[#issue_number] commit message`.
* Keep commits small, focused, squashed, and rebased before merging
* Follow the workflow described in [CONTRIBUTING.md](../CONTRIBUTING.md)

---

Thank you for contributing to **pgmoneta_mcp**!