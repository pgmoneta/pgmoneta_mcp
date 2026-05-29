#!/bin/bash
## Copyright (C) 2026 The pgmoneta community
##
## This program is free software: you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation, either version 3 of the License, or
## (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with this program. If not, see <https://www.gnu.org/licenses/>.
set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PGMONETA_DIR="$HOME/.pgmoneta"
readonly PGMONETA_MCP_DIR="$HOME/.pgmoneta-mcp"
readonly PGMONETA_MASTER_KEY_FILE="$PGMONETA_DIR/master.key"
readonly MCP_MASTER_KEY_FILE="$PGMONETA_MCP_DIR/master.key"
readonly TEST_SUITE_DIR_NAME="test-suite"
readonly TEST_SUITE_DIR="$SCRIPT_DIR/$TEST_SUITE_DIR_NAME"
readonly TEST_SUITE_IMAGE_HASH_FILE="$SCRIPT_DIR/.test-suite-image.sha256"
readonly TEST_MASTER_KEY="$TEST_SUITE_DIR/master.key"
readonly CONF_FILES="$TEST_SUITE_DIR/conf"
readonly BIN_DIR="$TEST_SUITE_DIR/usr/bin"
readonly PGMONETA_RUN_FILE="$BIN_DIR/run-pgmoneta.ci"
readonly POSTGRESQL_RUN_FILE="$BIN_DIR/run-postgresql.ci"
readonly MANAGEMENT_PORT=5002
readonly PGMONETA_PORT_ONE=5001
readonly PGMONETA_PORT_TWO=9100
readonly POSTGRESQL_PORT=5432
readonly POSTGRESQL_READY_FILE="/tmp/pgmoneta-postgresql-ready"
readonly COMPRESS_FIXTURE_FILE="/tmp/pgmoneta-mcp-compress-fixture.txt"
readonly DECOMPRESS_FIXTURE_SOURCE="/tmp/pgmoneta-mcp-decompress-fixture.txt"
readonly DECOMPRESS_FIXTURE_ARCHIVE="/tmp/pgmoneta-mcp-decompress-fixture.txt.zstd"
readonly ENCRYPT_FIXTURE_FILE="/tmp/pgmoneta-mcp-encrypt-fixture.txt"
readonly DECRYPT_FIXTURE_FILE="/tmp/pgmoneta-mcp-decrypt-fixture.txt"

MASTER_KEY_PATH=
IMAGE_REF=
RUN_REPLACE_FLAG=
GENERATE_NEW_IMAGE=false
TEST_SUITE_IMAGE_CHANGED=false
POSTGRES_PID=
PGMONETA_PID=

readonly CONTAINER_NAME="pgmoneta-container"
readonly IMAGE_NAME="pgmoneta-mcp-test-suite"

## Env vars
export PG_DATABASE=${PG_DATABASE:-"mydb"}
export PG_DATABASE_ENCODING=${PG_DATABASE_ENCODING:-UTF8}
export PG_USER_NAME=${PG_USER_NAME:-"myuser"}
export PG_USER_PASSWORD=${PG_USER_PASSWORD:-"mypass"}
export PG_NETWORK_MASK=${PG_NETWORK_MASK:-"all"}
export PG_PRIMARY_NAME=${PG_PRIMARY_NAME:-"localhost"}
export PG_PRIMARY_PORT=${PG_PRIMARY_PORT:-"5432"}
export PG_REPL_USER_NAME=${PG_REPL_USER_NAME:-"backup_user"}
export PG_REPL_USER_PASSWORD=${PG_REPL_USER_PASSWORD:-"backup_pass"}

## ================================
## Container operations
## ================================
get_container_engine() {
    if command -v podman >/dev/null 2>&1; then
        echo "podman"
    elif command -v docker >/dev/null 2>&1; then
        echo "docker"
    else
        echo "Error: Neither Docker nor Podman is installed" >&2
        exit 1
    fi
}

get_image_name() {
    local container_engine="$(get_container_engine)"

    if [[ "$container_engine" == "docker" ]]; then
        IMAGE_REF="$IMAGE_NAME"
        RUN_REPLACE_FLAG=""
    else
        IMAGE_REF="localhost/$IMAGE_NAME"
        RUN_REPLACE_FLAG="--replace"
    fi
}

start_container() {
    local container_engine="$(get_container_engine)"
    $container_engine run -p $MANAGEMENT_PORT:$MANAGEMENT_PORT -p $PGMONETA_PORT_ONE:$PGMONETA_PORT_ONE -p $PGMONETA_PORT_TWO:$PGMONETA_PORT_TWO -p $POSTGRESQL_PORT:$POSTGRESQL_PORT --name "$CONTAINER_NAME" -d -e PG_DATABASE="$PG_DATABASE" -e PG_USER_NAME="$PG_USER_NAME" -e PG_USER_PASSWORD="$PG_USER_PASSWORD" -e PG_NETWORK_MASK="$PG_NETWORK_MASK" -e PG_PRIMARY_NAME="$PG_PRIMARY_NAME" -e PG_PRIMARY_PORT="$PG_PRIMARY_PORT" -e PG_REPL_USER_NAME="$PG_REPL_USER_NAME" -e PG_REPL_USER_PASSWORD="$PG_REPL_USER_PASSWORD" $RUN_REPLACE_FLAG "$IMAGE_REF"
}

start_composed_container() {
    if [[ "$TEST_SUITE_IMAGE_CHANGED" == true ]]; then
        local container_engine="$(get_container_engine)"
        $container_engine rm -f "$CONTAINER_NAME" 2>/dev/null || true
    fi
    if check_container_exists; then
        prepare_compression_fixtures_container
        return 0
    fi
    echo "Starting composed container for testing..."
    check_port "$MANAGEMENT_PORT"
    check_port "$PGMONETA_PORT_ONE"
    check_port "$PGMONETA_PORT_TWO"
    check_port "$POSTGRESQL_PORT"
    cd "$TEST_SUITE_DIR"
    start_container
    cd "$SCRIPT_DIR"
    wait_for_pgmoneta_startup
    prepare_compression_fixtures_container
}

build_composed_image() {
    get_image_name
    local container_engine="$(get_container_engine)"
    local current_hash=""
    local previous_hash=""

    current_hash="$(
        find "$TEST_SUITE_DIR" -type f ! -name "$(basename "$TEST_SUITE_IMAGE_HASH_FILE")" -print0 \
            | sort -z \
            | xargs -0 sha256sum \
            | sha256sum \
            | awk '{print $1}'
    )"

    if [[ -f "$TEST_SUITE_IMAGE_HASH_FILE" ]]; then
        previous_hash="$(cat "$TEST_SUITE_IMAGE_HASH_FILE")"
    fi

    ## check if image name exists, if yes skip build
    if [[ "$GENERATE_NEW_IMAGE" == false ]] \
        && [[ "$current_hash" == "$previous_hash" ]] \
        && $container_engine images --format "{{.Repository}}" 2>/dev/null | grep -q "$IMAGE_REF"; then
        echo "Image '$IMAGE_REF' already exists. Skipping build."
        TEST_SUITE_IMAGE_CHANGED=false
        return 0
    fi
    if [[ "$current_hash" != "$previous_hash" ]]; then
        echo "Test suite sources changed. Rebuilding image '$IMAGE_REF'."
    fi
    $container_engine build --no-cache -t "$IMAGE_REF" .
    printf '%s\n' "$current_hash" > "$TEST_SUITE_IMAGE_HASH_FILE"
    TEST_SUITE_IMAGE_CHANGED=true
}

clean_composed_image() {
    local container_engine="$(get_container_engine)"
    $container_engine stop "$CONTAINER_NAME" 2>/dev/null || true
    $container_engine rm -f "$CONTAINER_NAME" 2>/dev/null || true
    $container_engine rmi -f "$IMAGE_REF" 2>/dev/null || true
    $container_engine rmi -f "$IMAGE_NAME" 2>/dev/null || true
}

check_container_exists() {
    local container_engine="$(get_container_engine)"
    local container_name="$CONTAINER_NAME"
    
    if $container_engine ps -a --format "{{.Names}}" 2>/dev/null | grep -q "$container_name"; then
        echo "Container '$container_name' already exists."
        
        if $container_engine ps --format "{{.Names}}" 2>/dev/null | grep -q "$container_name"; then
            echo "Container is already running. Skipping start."
            return 0
        else
            echo "Container exists but is stopped. Removing it for a fresh test environment..."
            $container_engine rm -f "$container_name" >/dev/null 2>&1 || true
            return 1
        fi
    fi
    return 1
}

stop_composed_container() {
    local container_engine="$(get_container_engine)"
    $container_engine stop "$CONTAINER_NAME" 2>/dev/null || true
}

## ================================
## Master key operations
## ================================

# private
## Master key is needed by the integration tests
setup_master_key() {
    if [[ -s "$MCP_MASTER_KEY_FILE" ]]; then
        echo "MCP master key already exists, skipping generation."
        chmod 700 "$PGMONETA_MCP_DIR"
        chmod 600 "$MCP_MASTER_KEY_FILE"
        MASTER_KEY_PATH="$MCP_MASTER_KEY_FILE"
    elif [[ -s "$PGMONETA_MASTER_KEY_FILE" ]]; then
        echo "Master key already exists, skipping generation."
        chmod 700 "$PGMONETA_DIR"
        chmod 600 "$PGMONETA_MASTER_KEY_FILE"
        MASTER_KEY_PATH="$PGMONETA_MASTER_KEY_FILE"
    else
        generate_master_key
    fi
}

## Generate the new master key using pgmoneta-admin utility (needs to be executed using non-root user)
generate_master_key() {
    mkdir -p "$PGMONETA_DIR"
    echo "Generating new master key..."
    chmod 700 "$PGMONETA_DIR"
    pgmoneta-admin -g master-key
    chmod 600 "$PGMONETA_MASTER_KEY_FILE"
    MASTER_KEY_PATH="$PGMONETA_MASTER_KEY_FILE"
    echo "Master key generated at $MASTER_KEY_PATH"
    GENERATE_NEW_IMAGE=true # since we have changed the master key.
}

# private
copy_master_key() {
    echo "Copying master key to test suite directory..."
    if [[ ! "$SUBCOMMAND" == "ci" ]]; then
        cat "$MASTER_KEY_PATH" > "$TEST_MASTER_KEY"
    fi
    mkdir -p "$PGMONETA_MCP_DIR"
    chmod 700 "$PGMONETA_MCP_DIR"
    if [[ "$MASTER_KEY_PATH" != "$MCP_MASTER_KEY_FILE" ]]; then
        cat "$MASTER_KEY_PATH" > "$MCP_MASTER_KEY_FILE"
    else
        echo "Master key source and destination are identical; skipping copy to avoid truncation."
    fi
    chmod 600 "$MCP_MASTER_KEY_FILE"
}

# api
handle_master_key() {
    setup_master_key
    copy_master_key
}
## ================================
## CI operations
## ================================
ci_create_pgmoneta_user() {
    if ! id -u pgmoneta >/dev/null 2>&1; then
        echo "Creating pgmoneta user and group..."
        useradd -r -m -d /home/pgmoneta -s /bin/bash pgmoneta
    else
        echo "pgmoneta user already exists, skipping creation."
    fi
}

ci_create_postgres_user() {
    if ! id -u postgres >/dev/null 2>&1; then
        echo "Creating postgres user and group..."
        useradd -r -s /bin/bash postgres
    else
        echo "postgres user already exists, skipping creation."
    fi
}

ci_create_users() {
    ci_create_pgmoneta_user
    ci_create_postgres_user
}

ci_check_postgres_running() {
    if ! nc -z localhost "$POSTGRESQL_PORT" 2>/dev/null; then
        echo "Error: PostgreSQL is not running on port $POSTGRESQL_PORT. Please start/install PostgreSQL before running CI tests."
        exit 1
    fi
}

ci_run_postgresql() {
    echo "Starting PostgreSQL for CI tests..."
    rm -f "$POSTGRESQL_READY_FILE"
    chmod a+x "$POSTGRESQL_RUN_FILE"
    "$POSTGRESQL_RUN_FILE" &
    POSTGRES_PID=$!
    ci_wait_for_postgresql
}

ci_wait_for_postgresql() {
    local max_wait=30
    local count=0

    until [[ -f "$POSTGRESQL_READY_FILE" ]] \
        && /usr/pgsql-18/bin/pg_isready -q -h localhost -p "$POSTGRESQL_PORT"; do
        if [ "$count" -ge "$max_wait" ]; then
            echo "PostgreSQL did not complete setup and become ready within ${max_wait}s"
            exit 1
        fi

        echo "Waiting for PostgreSQL..."
        sleep 1
        count=$((count + 1))
    done
}

ci_run_pgmoneta() {
    echo "Starting pgmoneta for CI tests..."
    chmod a+x "$PGMONETA_RUN_FILE"
    "$PGMONETA_RUN_FILE" &
    PGMONETA_PID=$!
    ci_wait_for_pgmoneta
}

ci_wait_for_pgmoneta() {
    local max_wait=30
    local count=0

    until nc -z localhost $MANAGEMENT_PORT; do
        if [ "$count" -ge "$max_wait" ]; then
            echo "pgmoneta did not become ready within ${max_wait}s"
            exit 1
        fi

        echo "Waiting for pgmoneta..."
        sleep 1
        count=$((count + 1))
    done
}

ci_install_libev_from_source() {
    local workdir="/tmp/libev-src"
    local tarball="$workdir/libev.tar.gz"
    local extracted_dir=""

    rm -rf "$workdir"
    mkdir -p "$workdir"

    # Prefer official release tarball; keep a mirror fallback.
    if ! curl --retry 3 --retry-all-errors --connect-timeout 2 -fsSL -o "$tarball" "https://dist.schmorp.de/libev/libev-4.33.tar.gz"; then
        if ! curl --retry 3 --retry-all-errors --connect-timeout 2 -fsSL -o "$tarball" "https://github.com/enki/libev/archive/refs/tags/v4.33.tar.gz"; then
            curl --retry 3 --retry-all-errors --connect-timeout 2 -fsSL -o "$tarball" "https://distfiles.macports.org/libev/libev-4.33.tar.gz"
        fi
    fi

    tar -xzf "$tarball" -C "$workdir"
    extracted_dir="$(find "$workdir" -mindepth 1 -maxdepth 1 -type d | head -n 1)"

    if [ -z "$extracted_dir" ]; then
        echo "Error: unable to extract libev source archive"
        return 1
    fi

    pushd "$extracted_dir" >/dev/null

    if [ -x ./configure ]; then
        ./configure --prefix=/usr
    else
        if [ -x ./autogen.sh ]; then
            ./autogen.sh
        fi
        ./configure --prefix=/usr
    fi

    make -j"$(nproc)"
    make install
    ldconfig || true

    popd >/dev/null
}

ci_install_libyaml_from_source() {
    local workdir="/tmp/libyaml-src"
    local tarball="$workdir/libyaml.tar.gz"
    local extracted_dir=""

    rm -rf "$workdir"
    mkdir -p "$workdir"

    if ! curl --retry 3 --retry-all-errors --connect-timeout 2 -fsSL -o "$tarball" "https://github.com/yaml/libyaml/archive/refs/tags/0.2.5.tar.gz"; then
        curl --retry 3 --retry-all-errors --connect-timeout 2 -fsSL -o "$tarball" "https://pyyaml.org/download/libyaml/yaml-0.2.5.tar.gz"
    fi

    tar -xzf "$tarball" -C "$workdir"
    extracted_dir="$(find "$workdir" -mindepth 1 -maxdepth 1 -type d | head -n 1)"

    if [ -z "$extracted_dir" ]; then
        echo "Error: unable to extract libyaml source archive"
        return 1
    fi

    pushd "$extracted_dir" >/dev/null

    if [ ! -x ./configure ]; then
        dnf install -y autoconf automake libtool
        if [ -x ./bootstrap ]; then
            ./bootstrap
        else
            autoreconf -fi
        fi
    fi

    ./configure --prefix=/usr
    make -j"$(nproc)"
    make install
    ldconfig || true
    popd >/dev/null
}

ci_install_utilities() {
    local arch
    arch="$(uname -m)"

    install_first_available_pkg() {
        for candidate in "$@"; do
            if dnf install -y "$candidate" >/dev/null 2>&1; then
                return 0
            fi
        done

        echo "Error: none of the candidate packages are available: $*"
        return 1
    }

    if ! curl --retry 3 --retry-all-errors --connect-timeout 2 -fsSL -o /tmp/epel-release.rpm "https://dl.fedoraproject.org/pub/epel/epel-release-latest-10.noarch.rpm"; then
        if ! curl --retry 3 --retry-all-errors --connect-timeout 2 -fsSL -o /tmp/epel-release.rpm "https://download.fedoraproject.org/pub/epel/epel-release-latest-10.noarch.rpm"; then
            curl --retry 3 --retry-all-errors --connect-timeout 2 -fsSL -o /tmp/epel-release.rpm "https://mirror.netone.nl/other/epel/epel-release-latest-10.noarch.rpm"
        fi
    fi
    rpm -Uvh /tmp/epel-release.rpm
    if ! curl --retry 3 --retry-all-errors --connect-timeout 2 -fsSL -o /tmp/pgdg.rpm "https://download.postgresql.org/pub/repos/yum/reporpms/EL-10-${arch}/pgdg-redhat-repo-latest.noarch.rpm"; then
        curl --retry 3 --retry-all-errors --connect-timeout 2 -fsSL -o /tmp/pgdg.rpm "https://ftp.postgresql.org/pub/repos/yum/reporpms/EL-10-${arch}/pgdg-redhat-repo-latest.noarch.rpm"
    fi
    rpm -Uvh /tmp/pgdg.rpm
    rm -f /tmp/epel-release.rpm /tmp/pgdg.rpm

    # EPEL notes that many packages (including devel headers) may require CRB.
    if command -v crb >/dev/null 2>&1; then
        crb enable || true
    fi

    dnf update -y
    dnf install -y cargo nmap-ncat git gcc clang cmake make

    # pgmoneta source build requires libev headers; install by pkg-config provide first.
    if ! dnf install -y libev 'pkgconfig(libev)'; then
        if dnf info -q libev-devel >/dev/null 2>&1; then
            dnf install -y libev libev-devel
        else
            echo "libev development package not available; building libev from source"
            ci_install_libev_from_source
        fi
    fi

    dnf install -y openssl openssl-devel systemd systemd-devel zlib zlib-devel
    install_first_available_pkg ncurses-devel 'pkgconfig(ncurses)'
    dnf install -y zstd lz4 libssh bzip2
    install_first_available_pkg zstd-devel libzstd-devel
    install_first_available_pkg lz4-devel liblz4-devel
    install_first_available_pkg cjson libcjson
    install_first_available_pkg cjson-devel libcjson-devel
    install_first_available_pkg libyaml yaml
    if ! install_first_available_pkg libyaml-devel yaml-devel 'pkgconfig(yaml-0.1)'; then
        echo "libyaml development package not available; building libyaml from source"
        ci_install_libyaml_from_source
    fi
    dnf install -y libssh-devel bzip2-devel
    dnf install -y libarchive libarchive-devel python3-docutils libatomic
    dnf install -y postgresql18 postgresql18-server postgresql18-contrib postgresql18-libs
}

ci_install_pgmoneta_from_main() {
    local repo_dir="/tmp/pgmoneta-main"

    echo "Installing pgmoneta from main branch..."
    rm -rf "$repo_dir"
    git clone --depth 1 --branch main https://github.com/pgmoneta/pgmoneta.git "$repo_dir"

    mkdir -p "$repo_dir/build"
    pushd "$repo_dir/build" >/dev/null
    cmake -DDOCS=false -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr ..
    make -j"$(nproc)"
    make install
    popd >/dev/null

    command -v pgmoneta >/dev/null 2>&1 || {
        echo "Error: pgmoneta binary not found after build/install"
        exit 1
    }
    command -v pgmoneta-admin >/dev/null 2>&1 || {
        echo "Error: pgmoneta-admin binary not found after build/install"
        exit 1
    }

    echo "Using pgmoneta version:"
    pgmoneta --version || true
}

ci_handle_master_key() {
    su - pgmoneta <<EOF
$(declare -f setup_master_key copy_master_key generate_master_key handle_master_key)
PGMONETA_DIR="\$HOME/.pgmoneta"
PGMONETA_MCP_DIR="\$HOME/.pgmoneta-mcp"
PGMONETA_MASTER_KEY_FILE="\$PGMONETA_DIR/master.key"
MCP_MASTER_KEY_FILE="\$PGMONETA_MCP_DIR/master.key"
SUBCOMMAND="ci"
MASTER_KEY_PATH=""
GENERATE_NEW_IMAGE=false
handle_master_key
EOF

    local master_key="/home/pgmoneta/.pgmoneta-mcp/master.key"
    mkdir -p "$PGMONETA_MCP_DIR"
    su - pgmoneta -c "cat '$master_key'" > "$MCP_MASTER_KEY_FILE"
    chmod 700 "$PGMONETA_MCP_DIR"
    chmod 600 "$MCP_MASTER_KEY_FILE"
}

ci_setup() {
    mkdir -p /pgdata /pgwal /pgmoneta /pglog
    ci_install_utilities
    ci_install_pgmoneta_from_main
    ci_create_users
    ci_handle_master_key
    cp "$CONF_FILES"/* /tmp/
    # Increase server verbosity in CI to aid protocol-interoperability debugging
    sed -i 's/^log_level = .*/log_level = debug/' /tmp/pgmoneta.conf || true
    ci_run_postgresql
    ci_run_pgmoneta
    prepare_compression_fixtures_local
}

prepare_compression_fixtures_local() {
    printf 'pgmoneta MCP compression fixture\n' > "$COMPRESS_FIXTURE_FILE"
    chmod 644 "$COMPRESS_FIXTURE_FILE"

    printf 'pgmoneta MCP decompression fixture\n' > "$DECOMPRESS_FIXTURE_SOURCE"
    zstd -q -f "$DECOMPRESS_FIXTURE_SOURCE" -o "$DECOMPRESS_FIXTURE_ARCHIVE"
    rm -f "$DECOMPRESS_FIXTURE_SOURCE"
    chmod 644 "$DECOMPRESS_FIXTURE_ARCHIVE"

    printf 'pgmoneta MCP encryption fixture\n' > "$ENCRYPT_FIXTURE_FILE"
    chmod 644 "$ENCRYPT_FIXTURE_FILE"
    printf 'pgmoneta MCP decryption fixture\n' > "$DECRYPT_FIXTURE_FILE"
    chmod 644 "$DECRYPT_FIXTURE_FILE"
}

prepare_compression_fixtures_container() {
    local container_engine="$(get_container_engine)"
    $container_engine exec "$CONTAINER_NAME" /bin/bash -lc "\
        printf 'pgmoneta MCP compression fixture\n' > '$COMPRESS_FIXTURE_FILE' && \
        chmod 644 '$COMPRESS_FIXTURE_FILE' && \
        printf 'pgmoneta MCP decompression fixture\n' > '$DECOMPRESS_FIXTURE_SOURCE' && \
        zstd -q -f '$DECOMPRESS_FIXTURE_SOURCE' -o '$DECOMPRESS_FIXTURE_ARCHIVE' && \
        rm -f '$DECOMPRESS_FIXTURE_SOURCE' && \
        chmod 644 '$DECOMPRESS_FIXTURE_ARCHIVE' && \
        printf 'pgmoneta MCP encryption fixture\n' > '$ENCRYPT_FIXTURE_FILE' && \
        chmod 644 '$ENCRYPT_FIXTURE_FILE' && \
        printf 'pgmoneta MCP decryption fixture\n' > '$DECRYPT_FIXTURE_FILE' && \
        chmod 644 '$DECRYPT_FIXTURE_FILE' && \
        chown pgmoneta:pgmoneta \
            '$COMPRESS_FIXTURE_FILE' \
            '$DECOMPRESS_FIXTURE_ARCHIVE' \
            '$ENCRYPT_FIXTURE_FILE' \
            '$DECRYPT_FIXTURE_FILE'"
}

ci_dump_logs() {
    echo "=== pgmoneta log (tail) ==="
    if [ -f /tmp/pgmoneta.log ]; then
        tail -n 300 /tmp/pgmoneta.log || true
    else
        echo "No /tmp/pgmoneta.log file found"
    fi
}

ci_shutdown() {
    echo "Stopping CI services..."
    ci_dump_logs
    [ -n "${PGMONETA_PID:-}" ] && kill -TERM "$PGMONETA_PID" >/dev/null 2>&1 || true
    [ -n "${POSTGRES_PID:-}" ] && kill -TERM "$POSTGRES_PID" >/dev/null 2>&1 || true
    sleep 1
    [ -n "${PGMONETA_PID:-}" ] && kill -KILL "$PGMONETA_PID" >/dev/null 2>&1 || true
    [ -n "${POSTGRES_PID:-}" ] && kill -KILL "$POSTGRES_PID" >/dev/null 2>&1 || true
    [ -n "${PGMONETA_PID:-}" ] && wait "$PGMONETA_PID" 2>/dev/null || true
    [ -n "${POSTGRES_PID:-}" ] && wait "$POSTGRES_PID" 2>/dev/null || true
    rm -f "$POSTGRESQL_READY_FILE"
}

## ================================
## Test suite operations
## ================================
build_test_suite() {
    echo "Building test suite container..."
    cd "$TEST_SUITE_DIR"
    build_composed_image
    cd "$SCRIPT_DIR"
}

check_port() {
    local port="$1"
    if nc -z localhost "$port" 2>/dev/null; then
        echo "Error: Port $port is already in use. Stop the process using it or change the port configuration"
        exit 1
    fi
}

wait_for_pgmoneta_startup() {
    ci_wait_for_pgmoneta
}


remove_target_directory_if_exists() {
    local target_dir="$SCRIPT_DIR/../target"
    if [[ -d "$target_dir" ]]; then
        echo "Removing existing target directory..."
        rm -rf "$target_dir"
    fi
}

cleanup() {
    echo "Cleaning up test suite environment..."
    remove_target_directory_if_exists
    cd "$TEST_SUITE_DIR"
    get_image_name
    clean_composed_image
    cd "$SCRIPT_DIR"
}

show_status() {
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "                pgmoneta-mcp Test Environment Status               "
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    # Container engine
    local engine
    engine="$(get_container_engine)"
    echo "Engine   : $engine"

    # Image
    get_image_name
    if $engine images --format "{{.Repository}}" 2>/dev/null | grep -q "$IMAGE_NAME"; then
        echo "Image    : $IMAGE_NAME (found)"
    else
        echo "Image    : $IMAGE_NAME (not built)"
    fi

    # Container
    if $engine ps --format "{{.Names}}" 2>/dev/null | grep -q "$CONTAINER_NAME"; then
        echo "Container: $CONTAINER_NAME (running)"
    elif $engine ps -a --format "{{.Names}}" 2>/dev/null | grep -q "$CONTAINER_NAME"; then
        echo "Container: $CONTAINER_NAME (stopped)"
    else
        echo "Container: $CONTAINER_NAME (not created)"
    fi

    echo ""

    # Ports
    echo "Ports:"
    local ports=( 
        "$MANAGEMENT_PORT (Management) " 
        "$PGMONETA_PORT_ONE (PgmonetaOne)" 
        "$PGMONETA_PORT_TWO (PgmonetaTow)" 
        "$POSTGRESQL_PORT (PostgreSQL) " 
    )
    for p_info in "${ports[@]}"; do
        local port="${p_info%% *}"
        local label="${p_info#* }"
        if nc -z localhost "$port" 2>/dev/null; then
            echo "   $port $label: in use"
        else
            echo "   $port $label: free"
        fi
    done

    echo ""

    # Master key
    echo "Auth:"
    if [[ -s "$MCP_MASTER_KEY_FILE" ]]; then
        echo "   Master key: found ($MCP_MASTER_KEY_FILE)"
    elif [[ -s "$PGMONETA_MASTER_KEY_FILE" ]]; then
        echo "   Master key: found ($PGMONETA_MASTER_KEY_FILE)"
    else
        echo "   Master key: not found"
    fi
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

install_dependencies() {
    echo "Installing dependencies..."
    dnf update -y
    dnf install -y cargo # currently we just need cargo to run pgmoneta-mcp, others are installed in the ci or by docker/podman
}

run_info_test_matrix() {
    echo "Running full compression/encryption info_test matrix..."
    for comp in none gzip zstd lz4 bzip2; do
        for enc in none aes_128_gcm aes_192_gcm aes_256_gcm; do
            echo "Matrix mode: compression=$comp encryption=$enc"
            PGMONETA_MCP_COMPRESSION="$comp" PGMONETA_MCP_ENCRYPTION="$enc" cargo test --test info_test -- --test-threads=1 --nocapture --include-ignored
        done
    done
}

## ================================
## Main script logic
## ================================
usage() {
   echo "Usage: $0 [options] [sub-command]"
   echo "Subcommands:"
   echo " setup          Install Dependencies e.g (Rust, Cargo) required for building and running tests"
   echo " build          Set up environment (build, postgreSQL and pgmoneta composed image) without running tests"
   echo " clean          Clean up test suite environment and remove the composed image"
    echo " test           Starts the composed container and runs the full test suite"
   echo " integration    Starts the composed container and run only integration tests (clean + build + integration)"
    echo " unit           Clean + build environment, then run only unit tests"
    echo " unit-only      Alias for 'unit'"
    echo " ci             Run only the 20-mode info_test matrix with CI-specific settings"
   echo " status         Show test environment status (image, container, ports, master key)"
   echo "Options (run tests with optional filter; default is full suite):"
   echo " -m, --module NAME   Run all tests in module NAME"
   echo "Examples:"
    echo "  $0                  Run full test suite"
    echo "  $0 test             Run full test suite"
   echo "  $0 build            Set up environment only; then run e.g. $0 test -m security"
   echo "  $0 test -m security       Run all tests in module 'security'"
   echo "  $0 integration -m info_test    Run integration tests in module 'info_test'"
   exit 1
}

MODULE_FILTER=""
SUBCOMMAND=""
while [[ $# -gt 0 ]]; do
case "$1" in
    -m|--module)
        shift
        [[ $# -eq 0 ]] && { echo "Error: -m/--module requires NAME"; usage; }
        MODULE_FILTER="$1"
        shift
        ;;
    setup)
        [[ -n "$SUBCOMMAND" ]] && usage
        SUBCOMMAND="setup"
        shift
        ;;
    build)
        [[ -n "$SUBCOMMAND" ]] && usage
        SUBCOMMAND="build"
        shift
        ;;
    clean)
        [[ -n "$SUBCOMMAND" ]] && usage
        SUBCOMMAND="clean"
        shift
        ;;
    test)
        [[ -n "$SUBCOMMAND" ]] && usage
        SUBCOMMAND="test"
        shift
        ;;
    integration)
        [[ -n "$SUBCOMMAND" ]] && usage
        SUBCOMMAND="integration"
        shift
        ;;
    unit)
        [[ -n "$SUBCOMMAND" ]] && usage
        SUBCOMMAND="unit"
        shift
        ;;
    unit-only)
        [[ -n "$SUBCOMMAND" ]] && usage
        SUBCOMMAND="unit"
        shift
        ;;
    ci)
        [[ -n "$SUBCOMMAND" ]] && usage
        SUBCOMMAND="ci"
        shift
        ;;
    status)
        [[ -n "$SUBCOMMAND" ]] && usage
        SUBCOMMAND="status"
        shift
        ;;
    -h|--help)
        usage
        ;;
    -*)
        echo "Invalid option: $1"
        usage
        ;;
    *)
        echo "Invalid parameter: $1"
        usage
        ;;
esac
done

if [[ -n "$MODULE_FILTER" ]] && [[ -n "$SUBCOMMAND" ]] && \
    [[ "$SUBCOMMAND" != "test" ]] && [[ "$SUBCOMMAND" != "integration" ]] && [[ "$SUBCOMMAND" != "unit" ]]; then
    echo "Error: -m/--module option can only be used with 'test', 'integration', or 'unit' subcommands, or no subcommand"
    usage
fi

case "$SUBCOMMAND" in
    setup)
        install_dependencies
        echo "Dependencies installed."
        ;;
    build)
        handle_master_key
        build_test_suite
        echo "Test suite environment set up."
        ;;
    clean)
        cleanup
        echo "Test suite environment cleaned."
        ;;
    status)
        show_status
        ;;
    test)
        handle_master_key
        build_test_suite
        start_composed_container
        trap stop_composed_container EXIT
        run_info_test_matrix
        if [[ -n "$MODULE_FILTER" ]]; then
            cargo test --all-features -- --test-threads=1 --nocapture --include-ignored -- $MODULE_FILTER
        else
            cargo test --all-features -- --test-threads=1 --nocapture --include-ignored
        fi
        ;;
    integration)
        handle_master_key
        build_test_suite
        start_composed_container
        trap stop_composed_container EXIT
        if [[ -n "$MODULE_FILTER" ]]; then
            cargo test --test "*" -- --test-threads=1 --nocapture --include-ignored -- $MODULE_FILTER
        else
            cargo test --test "*" -- --test-threads=1 --nocapture --include-ignored
        fi
        ;;
    unit)
        cleanup
        handle_master_key
        build_test_suite
        if [[ -n "$MODULE_FILTER" ]]; then
            cargo test --lib -- --test-threads=1 --nocapture -- $MODULE_FILTER
        else
            cargo test --lib -- --test-threads=1 --nocapture
        fi
        ;;
    ci)
        trap ci_shutdown EXIT
        ci_setup
        run_info_test_matrix

        echo "Skipping default cargo test suite in ci mode; unit tests are handled in dedicated CI jobs."
        ;;
    "")
        cleanup
        handle_master_key
        build_test_suite
        start_composed_container
        trap stop_composed_container EXIT
        run_info_test_matrix
        if [[ -n "$MODULE_FILTER" ]]; then
            cargo test -- --test-threads=1 --nocapture --include-ignored -- $MODULE_FILTER
        else
            cargo test -- --test-threads=1 --nocapture --include-ignored
        fi
        ;;
esac
