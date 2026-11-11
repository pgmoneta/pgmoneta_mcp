# Test

## Dependencies

To install all the required dependencies (rust, make and cargo), simply run `<PATH_TO_PGMONETA_MCP>/test/check.sh setup`. You need to install docker or podman
separately. The script currently only works on Linux system (we recommend Fedora 39+).

Test execution prefers [cargo-nextest](https://nexte.st/) when it is installed
(see `.config/nextest.toml`). If nextest is missing, `test/check.sh` falls back
to `cargo test`. Install nextest with:

```bash
curl -LsSf https://get.nexte.st/latest/linux | tar zxf - -C ${CARGO_HOME:-~/.cargo}/bin
```

## Running Tests

To run the tests, simply run `<PATH_TO_PGMONETA_MCP>/test/check.sh`. The script will build a composed image containing PostgreSQL 18 and pgmoneta, start a docker/podman container using the image (so make sure you at least have one of them installed and have the corresponding container engine started), and run the regular test suite. 
The containerized pgmoneta-postgres composed server will have a `backup_user` user with the replication attribute, a normal user `myuser` and a database `mydb`.

The script then runs pgmoneta_mcp tests in your local environment. The tests are run locally so that you may leverage stdout to debug.

## Build only (no tests) 
Run `<PATH_TO_PGMONETA>/test/check.sh build` to prepare the test environment (image, master key generation) without running tests. This always does a full build.

## Fast Iteration of testing
Run `<PATH_TO_PGMONETA_MCP>/test/check.sh test` to run the full test suite without rebuilding the composed image.

## Unit tests
To run unit tests only, simply run `<PATH_TO_PGMONETA_MCP>/test/check.sh unit` (or `<PATH_TO_PGMONETA_MCP>/test/check.sh unit-only`). This mode performs clean + build setup first, then runs unit tests.

## Integration tests
To run integration tests only, simply run `<PATH_TO_PGMONETA_MCP>/test/check.sh integration`

## CI matrix-only mode
To run CI integration coverage only, run `<PATH_TO_PGMONETA_MCP>/test/check.sh ci`. This mode runs only the 20-combination `info_test` matrix and skips the regular full test suite.

## Single test or module
Run `<PATH_TO_PGMONETA>/test/check.sh test -m <test_name>`. The script assumes the environment is up, so you need to run the full suite first. For quick iteration, run `<PATH_TO_PGMONETA>/test/check.sh build` once, then `<PATH_TO_PGMONETA>/test/check.sh test -m <module_name>` or `<PATH_TO_PGMONETA>/test/check.sh test` repeatedly.

It is recommended that you **ALWAYS** run tests before raising PR.

## Add Testcases

To add an additional testcase, check [Test Organization in Rust](https://doc.rust-lang.org/book/ch11-03-test-organization.html)

## Cleanup

`<PATH_TO_PGMONETA>/test/check.sh clean` will remove the built image. If you are using docker, chances are it eats your 
disk space secretly, in that case consider cleaning up using `docker system prune --volume`. Use with caution though as it
nukes all the docker volumes.

## Port

By default, the container exposes port 5432 for pgmoneta-mcp to connect to.