\newpage

# OpenAI API

The native `pgmoneta-mcp-client` uses the OpenAI API for natural-language
requests. The model chooses pgmoneta MCP tools through OpenAI function calling;
the client executes those tools and returns their results to the model.

For a local deployment, use `orangu-server`. It provides the OpenAI endpoint
used in this example.

## Quick setup

``` sh
orangu-server -i
orangu-server download ggml-org/gemma-4-E4B-it-GGUF
orangu-server --all ggml-org/gemma-4-E4B-it-GGUF
```

Configure the native client:

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

Then start it:

``` sh
pgmoneta-mcp-client -c pgmoneta-mcp-client.conf -u pgmoneta-mcp-users.conf
```

The model must support OpenAI function calling, and its name must match one
returned by `/v1/models`. Other OpenAI API servers may work, but configuring or
operating them is outside the scope of this manual.
