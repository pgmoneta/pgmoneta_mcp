# Local LLM with orangu-server

`pgmoneta-mcp-client` supports the OpenAI API. This guide uses
`orangu-server` as the local OpenAI API server.

## Setup

1. Initialize orangu-server:

``` sh
orangu-server -i
```

2. Download a tool-capable model:

``` sh
orangu-server download ggml-org/gemma-4-E4B-it-GGUF
```

3. Serve the model:

``` sh
orangu-server --all ggml-org/gemma-4-E4B-it-GGUF
```

The OpenAI API is now available at `http://localhost:8100/v1`.

4. Create `pgmoneta-mcp-client.conf`:

``` ini
[pgmoneta_mcp_client]
url = http://localhost:6432/mcp
timeout = 30
model = gemma

[gemma]
provider = openai
endpoint = http://localhost:8100/v1
model = ggml-org/gemma-4-E4B-it-GGUF
max_tool_rounds = 10
```

5. Start the client:

``` sh
pgmoneta-mcp-client -c pgmoneta-mcp-client.conf -u pgmoneta-mcp-users.conf
```

Ask a natural-language question such as:

``` text
List backups for server primary
```

The model must support OpenAI function calling. The configured `model` must
match a model returned by the server's `/v1/models` endpoint.

Any server that implements the required OpenAI API may be used.
