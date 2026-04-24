\newpage

## Test

### Overview

**pgmoneta_mcp** includes comprehensive test coverage at multiple levels:

- **Unit tests**: Test individual functions and modules in isolation
- **Integration tests**: Test end-to-end functionality with a running pgmoneta server
- **Container-based tests**: Automated testing with Docker/Podman containers

All tests are written using Rust's built-in testing framework. For project-level integration coverage, use `test/check.sh`; for Rust-only execution, use `cargo test`.

### Dependencies

To install all the required dependencies (rust, make and cargo), simply run `<PATH_TO_PGMONETA_MCP>/test/check.sh setup`. You need to install docker or podman
separately. The script currently only works on Linux system (we recommend Fedora 39+). 

**Required dependencies**:
- Rust toolchain (stable)
- cargo
- docker or podman (for container-based tests)
- make (optional, for convenience scripts)

### Test Types

#### Unit Tests

Unit tests are embedded in the source files using `#[cfg(test)]` modules. They test individual functions and modules without external dependencies.

**Running unit tests**:
```bash
cargo test --lib
```

**Running specific unit test**:
```bash
cargo test test_base64_encode_decode
```

**Running tests with output**:
```bash
cargo test -- --nocapture
```

**Available unit test modules**:

**Security module tests** (`src/security.rs`):
- `test_base64_encode_decode`: Base64 encoding/decoding
- `test_encrypt_decrypt`: Encryption/decryption roundtrip
- `test_encrypt_decrypt_empty_string`: Empty string encryption
- `test_encrypt_decrypt_large_text`: Large text encryption (10KB)
- `test_encrypt_decrypt_unicode`: Unicode text encryption
- `test_decrypt_with_wrong_key`: Wrong key detection
- `test_decrypt_invalid_base64`: Invalid Base64 handling
- `test_decrypt_truncated_ciphertext`: Truncated data handling
- `test_generate_password_default_length`: Password generation (64 chars)
- `test_generate_password_custom_length`: Password generation (32 chars)
- `test_generate_password_contains_valid_chars`: Character set validation
- `test_generate_password_min_length`: Minimum length (1 char)
- `test_generate_password_uniqueness`: Random uniqueness
- `test_encrypt_different_nonces`: Nonce randomness

**Client module tests** (`src/client.rs`):
- `test_build_request_header`: Request header construction
- `test_build_request_header_different_commands`: Command differentiation
- `test_request_serialization`: JSON serialization
- `test_request_header_serialization`: Header serialization
- `test_write_request_format`: Wire format validation
- `test_timestamp_format`: Timestamp format validation
- `test_request_clone`: Request cloning

#### Integration Tests

Integration tests verify end-to-end functionality using a running pgmoneta server. Most integration tests are located in `tests/info_test.rs` and `tests/list_backup_test.rs`, and they are designed to be run against a matrix of security and compression settings.

**Running integration tests**:
```bash
# Run non-ignored integration tests (local handler tests)
cargo test --test handler_test

# Run ignored integration tests that require pgmoneta stack
cargo test --test info_test -- --ignored
cargo test --test list_backup_test -- --ignored
```

**Note**: Integration tests require a running pgmoneta stack (see `test/check.sh`).

**Available integration tests**:

- `info_test` (`tests/info_test.rs`, ignored): Get backup information. In CI, this is run as a **20-combination matrix** (5 compression modes × 4 encryption modes).
- `list_backup_test` (`tests/list_backup_test.rs`, ignored): List backups for a server.
- `test_handler_initialization` (`tests/handler_test.rs`): Verifies MCP handler initialization and capability reporting.
- `test_handler_default_trait` (`tests/handler_test.rs`): Verifies `Default` trait implementation for the handler.

### Running Tests

#### Quick Test Run (Unit Tests Only)

```bash
cargo test
```

This runs all unit tests without requiring external dependencies.

#### Full Test Suite (with Container)

To run the tests, simply run `<PATH_TO_PGMONETA_MCP>/test/check.sh`. The script will build a composed image containing PostgreSQL 18 and pgmoneta, start a docker/podman container using the image (so make sure you at least have one of them installed and have the corresponding container engine started) and run tests. 

The containerized pgmoneta-postgres composed server will have a `backup_user` user with the replication attribute, a normal user `myuser` and a database `mydb`.

The script then runs pgmoneta_mcp tests in your local environment. The tests are run locally so that you may leverage stdout to debug.

#### Build only (no tests) 

Run `<PATH_TO_PGMONETA>/test/check.sh build` to prepare the test environment (image, master key generation) without running tests. This always does a full build.

### Fast Iteration of testing
Run `<PATH_TO_PGMONETA_MCP>/test/check.sh test` to run the full test suite without rebuilding the composed image.

### Unit tests
To run unit tests only, simply run `<PATH_TO_PGMONETA_MCP>/test/check.sh unit`

### Integration tests
To run integration tests only, simply run `<PATH_TO_PGMONETA_MCP>/test/check.sh integration`

### CI matrix-only mode
To run CI integration coverage only, run `<PATH_TO_PGMONETA_MCP>/test/check.sh ci`. This mode runs only the 20-combination `info_test` matrix and skips the regular full test suite.

### Single test or module
Run `<PATH_TO_PGMONETA>/test/check.sh test -m <test_name>`. The script assumes the environment is up, so you need to run the full suite first. For quick iteration, run `<PATH_TO_PGMONETA>/test/check.sh build` once, then `<PATH_TO_PGMONETA>/test/check.sh test -m <module_name>` or `<PATH_TO_PGMONETA>/test/check.sh test` repeatedly.

#### Parallel vs Sequential Testing

By default, Rust runs tests in parallel. For integration tests that share resources, run sequentially:

```bash
cargo test -- --test-threads=1 --ignored
```

It is recommended that you **ALWAYS** run tests before raising PR.

### Writing New Tests

#### Adding Unit Tests

Unit tests should be added to the same file as the code they test, in a `#[cfg(test)]` module at the end of the file:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_my_function() {
        let result = my_function(input);
        assert_eq!(result, expected);
    }

    #[tokio::test]
    async fn test_async_function() {
        let result = async_function().await;
        assert!(result.is_ok());
    }
}
```

**Best practices**:
- Test both success and failure cases
- Test edge cases (empty input, large input, invalid input)
- Test error handling
- Use descriptive test names
- Keep tests focused and independent
- Use `assert_eq!`, `assert!`, `assert_ne!` for clear assertions

#### Adding Integration Tests

Integration tests should be added to `tests/integration_test.rs`:

```rust
#[tokio::test]
#[ignore] // Mark as ignored if requires external dependencies
async fn test_new_feature() {
    // Initialize configuration if needed
    if let Err(e) = init_config() {
        eprintln!("Skipping test: {}", e);
        return;
    }

    // Test implementation
    let handler = PgmonetaHandler::new();
    let result = handler.new_feature().await;
    
    assert!(result.is_ok());
}
```

**Best practices**:
- Mark tests requiring external dependencies with `#[ignore]`
- Handle missing configuration gracefully
- Provide clear error messages
- Clean up resources after tests
- Test realistic scenarios

For more details, check [Test Organization in Rust](https://doc.rust-lang.org/book/ch11-03-test-organization.html)

### Test Coverage

To generate test coverage reports:

```bash
# Install tarpaulin
cargo install cargo-tarpaulin

# Generate coverage report
cargo tarpaulin --out Html --output-dir coverage
```

Open `coverage/index.html` to view the coverage report.

**Current coverage areas**:
- Security module: Encryption, decryption, key management, password generation
- Client module: Request building, serialization, wire format
- Handler module: MCP tool routing, response translation
- Configuration module: Configuration loading and validation

### Debugging Tests

#### Enable Debug Logging

Set the `RUST_LOG` environment variable:

```bash
RUST_LOG=debug cargo test -- --nocapture
```

#### Run Single Test with Output

```bash
cargo test test_name -- --nocapture --test-threads=1
```

#### Use `dbg!` Macro

```rust
#[test]
fn test_debug() {
    let value = compute_value();
    dbg!(&value); // Prints value with file and line number
    assert_eq!(value, expected);
}
```

#### Conditional Compilation for Test Code

```rust
#[cfg(test)]
fn test_helper() {
    // Helper function only available in tests
}
```

### Continuous Integration

Tests are automatically run in CI/CD pipelines. The CI configuration includes:

- **Formatting check**: `cargo fmt --all --check`
- **Linting**: `cargo clippy --all-targets --all-features -- -D warnings`
- **Unit tests**: `cargo test --lib`
- **Build verification**: `cargo build --release`

### Cleanup

`<PATH_TO_PGMONETA>/test/check.sh clean` will remove the built image. If you are using docker, chances are it eats your 
disk space secretly, in that case consider cleaning up using `docker system prune --volume`. Use with caution though as it
nukes all the docker volumes.

### Port

By default, the container exposes port 5432 for pgmoneta-mcp to connect to.

### Troubleshooting

#### Tests Fail with "Configuration not found"

Ensure configuration files are in the expected locations:
- `pgmoneta-mcp.conf`
- `pgmoneta-mcp-users.conf`
- `~/.pgmoneta-mcp/master.key`

#### Integration Tests Timeout

Increase timeout or check if pgmoneta server is running:

```bash
# Check if pgmoneta is running
ps aux | grep pgmoneta

# Check if port is listening
netstat -tuln | grep 5000
```

#### Tests Fail with "Connection refused"

Ensure pgmoneta server is running and accessible:

```bash
# Start pgmoneta server
pgmoneta -c /path/to/pgmoneta.conf

# Or use the test container
./test/check.sh build
```

#### Permission Denied on Master Key

Fix file permissions:

```bash
chmod 600 ~/.pgmoneta-mcp/master.key
```

### Test Maintenance

- Keep tests up to date with code changes
- Remove obsolete tests
- Update test data when APIs change
- Document test requirements
- Review test failures in CI/CD
- Add tests for bug fixes
- Maintain test coverage above 80%
