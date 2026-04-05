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

For day-to-day development, prefer `test/check.sh`.

### Full local run

Runs the full local test flow.

```bash
bash test/check.sh
# or
bash test/check.sh test
```

### CI integration run (matrix only)

Runs only the 20-combination `info_test` matrix.

```bash
bash test/check.sh ci
```

### Unit tests only (with clean/build setup)

```bash
bash test/check.sh unit
# alias
bash test/check.sh unit-only
```

This mode performs `clean + build` setup first, then runs `cargo test --lib`.

### Integration tests only

```bash
bash test/check.sh integration
```

### Filter tests by module/pattern

```bash
bash test/check.sh -m security
bash test/check.sh unit -m compression
bash test/check.sh integration -m info_test
```

### Direct Cargo commands

You can still run Cargo directly:

```bash
cargo test
cargo test -- --nocapture
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
./target/debug/pgmoneta-mcp-server -c pgmoneta-mcp.conf -u pgmoneta-mcp-users.conf
./target/debug/pgmoneta-mcp-admin -f pgmoneta-mcp-users.conf user ls
./target/debug/pgmoneta-mcp-admin -f pgmoneta-mcp-users.conf -U admin user add
```

For a full list of admin commands, see [ADMIN.md](ADMIN.md).

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

## MCP Inspector

The `pgmoneta-mcp-inspector` is a command-line developer tool for testing and debugging the MCP server.
It serves the same purpose as the [MCP Inspector](https://modelcontextprotocol.io/docs/tools/inspector), allowing you to list tools, call them, and inspect responses directly from the terminal.

The built-in CLI inspector reads server connection details from a dedicated configuration file.

Create `pgmoneta-mcp-inspector.conf`:

```ini
[inspector]
url = http://localhost:8000/mcp
timeout = 30
```

Run with the config file:

```sh
pgmoneta-mcp-inspector inspector -c pgmoneta-mcp-inspector.conf tool list
```

Example tool call:

```sh
pgmoneta-mcp-inspector inspector -c pgmoneta-mcp-inspector.conf tool call <tool_name_with_args> '{"key": "value"}'
```

```sh
pgmoneta-mcp-inspector inspector -c pgmoneta-mcp-inspector.conf tool call <tool_name_without_args>
```

Interactive mode can be started explicitly or by running with no command:

```sh
pgmoneta-mcp-inspector interactive
pgmoneta-mcp-inspector
```

For full CLI reference, see the **MCP Inspector** chapter.

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

## Basic git guide

Here are some links that will help you

* [How to Squash Commits in Git](https://www.git-tower.com/learn/git/faq/git-squash)
* [ProGit book](https://github.com/progit/progit2/releases)

### Start by forking the repository

This is done by the "Fork" button on GitHub.

### Clone your repository locally

This is done by

```sh
git clone git@github.com:<username>/pgmoneta.git
```

### Add upstream

Do

```sh
cd pgmoneta
git remote add upstream https://github.com/pgmoneta/pgmoneta.git
```

### Do a work branch

```sh
git checkout -b mywork main
```

### Make the changes

Remember to verify the compile and execution of the code

### AUTHORS

Remember to add your name to the following files,

```
AUTHORS
doc/manual/en/97-acknowledgement.md
```

in your first pull request

### Multiple commits

If you have multiple commits on your branch then squash them

``` sh
git rebase -i HEAD~2
```

for example. It is `p` for the first one, then `s` for the rest

### Rebase

Always rebase

``` sh
git fetch upstream
git rebase -i upstream/main
```

### Force push

When you are done with your changes force push your branch

``` sh
git push -f origin mywork
```

and then create a pull requests for it

### Repeat

Based on feedback keep making changes, squashing, rebasing and force pushing

### PTAL

When you are working on a change put it into Draft mode, so we know that you are not
happy with it yet.

Please, send a PTAL to the Committer that were assigned to you once you think that
your change is complete. And, of course, take it out of Draft mode.

### Undo

Normally you can reset to an earlier commit using `git reset <commit hash> --hard`.
But if you accidentally squashed two or more commits, and you want to undo that,
you need to know where to reset to, and the commit seems to have lost after you rebased.

But they are not actually lost - using `git reflog`, you can find every commit the HEAD pointer
has ever pointed to. Find the commit you want to reset to, and do `git reset --hard`.

---

## Contributing Notes

* Add yourself to the `AUTHORS` and `doc/manual/en/97-acknowledgement.md` files in your first pull request
* When committing, use the format `[#issue_number] commit message`.
* Keep commits small, focused, squashed, and rebased before merging
* Follow the workflow described in [CONTRIBUTING.md](../CONTRIBUTING.md)

---

Thank you for contributing to **pgmoneta_mcp**!
