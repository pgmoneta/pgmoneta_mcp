
## RamaLama

[RamaLama](https://ramalama.ai) is an open-source command-line interface and unified AI gateway that simplifies the deployment and inference of AI models using containerization (Podman or Docker). It provides an OpenAI-compatible REST API, making it easy to integrate with **pgmoneta_mcp**.

Using `RamaLama` with `pgmoneta-mcp` allows you to leverage various runtimes (like `llama.cpp` or `vLLM`) through a single, stable interface.

### Install

To use `RamaLama`, you need to install the CLI. On Fedora and other RPM-based distributions, it is available via:

``` sh
dnf install ramalama
```

For other platforms, follow the instructions at [ramalama.ai](https://ramalama.ai).

### Download models

RamaLama automatically handles pulling models from registries like Hugging Face or OCI. You can pull a model explicitly:

``` sh
ramalama pull granite-code
```

### Start the server

Start the RamaLama server using your chosen model. RamaLama will automatically run the model inside a container:

``` sh
ramalama serve granite-code
```

The default endpoint will be `http://localhost:8080`.

### Configure pgmoneta_mcp

Add or update the `[llm]` section in `pgmoneta-mcp.conf`:

``` ini
[llm]
provider = ramalama
endpoint = http://localhost:8080
model = granite-3.0-8b-instruct
max_tool_rounds = 10
```

### Quick verification

Confirm the server is running:

``` sh
curl http://localhost:8080/v1/models
```

Start **pgmoneta_mcp**:

``` sh
pgmoneta-mcp-server -c pgmoneta-mcp.conf -u pgmoneta-mcp-users.conf
```

Open your MCP client and ask a question about your backups to verify end-to-end setup.