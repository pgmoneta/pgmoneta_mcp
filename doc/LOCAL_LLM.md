# Local LLM Installation

This guide focuses on installing and configuring a local LLM runtime for pgmoneta MCP.
It is intentionally scoped to local setup and does not cover chat examples or internal
implementation details.

## Scope

This guide covers:

* Installing Ollama, RamaLama, llama.cpp, or vLLM
* Downloading and validating a model
* Configuring the `[llm]` section in `pgmoneta-mcp.conf`

## Selecting a model

When choosing an LLM for **pgmoneta_mcp**, keep these key concepts in mind regardless of which provider you choose:

1. **Instruct vs. Base**: You must use a model fine-tuned for instruction following or chat (usually labeled `Instruct` or `Chat`). Base models are not trained to follow instructions and will fail at tool calling.
2. **Quantization**: Models are compressed ("quantized") to fit into consumer hardware. The default standard is **Q4** (4-bit quantization), which provides an excellent balance of speed, size, and reasoning quality.
3. **Hardware Limits**: The model's listed file size indicates the *minimum* RAM needed simply to load its weights. Actual runtime usage will be 20-30% higher because the runtime allocates memory for context caching and inference buffers.

### Model Compatibility Matrix

The model must support **tool calling** (function calling) to work with pgmoneta MCP tools.

| Model | Size | RAM Needed | Ollama | RamaLama | llama.cpp | vLLM | Notes |
| :---- | :--- | :--------- | :----- | :------- | :-------- | :--- | :---- |
| `granite-code` | ~5.0 GB | ~8 GB | Yes | Yes | Yes (GGUF) | Yes | **Recommended**. Built for coding and tool-calling |
| `llama3.1:8b` | ~4.7 GB | ~8 GB | Yes | Yes | Yes (GGUF) | Yes | Best balance of capability and size |
| `llama3.2:3b` | ~2.0 GB | ~4 GB | Yes | Yes | Yes (GGUF) | Yes | Lightweight option for limited hardware |
| `qwen2.5:7b` | ~4.7 GB | ~8 GB | Yes | Yes | Yes (GGUF) | Yes | Excellent tool calling capabilities |
| `mistral:7b` | ~4.1 GB | ~8 GB | Yes | Yes | Yes (GGUF) | Yes | Strong performance for open-source models |

## Ollama

[Ollama](https://ollama.com) is the recommended provider for running open-source models locally. It provides a simple CLI and API for downloading, managing, and serving LLM models.

### Basic Setup (Rocky Linux 10)

Install Ollama using the official script:

```sh
curl -fsSL https://ollama.com/install.sh | sh
```

Start the Ollama server as a background service:

```sh
ollama serve
```

Pull the recommended model:

```sh
ollama pull llama3.1:8b
```

### pgmoneta-mcp.conf Example

```ini
[llm]
provider = ollama
endpoint = http://localhost:11434
model = llama3.1:8b
max_tool_rounds = 10
```

## llama.cpp

[llama.cpp](https://github.com/ggml-org/llama.cpp) provides direct control over hardware and inference settings for running LLMs locally.

### Basic Setup (Rocky Linux 10)

You must download the `llama-server` binary and the model file manually. 

```sh
dnf install wget
```

Download the latest `llama-server` from the [official releases](https://github.com/ggml-org/llama.cpp/releases), and download a `.gguf` model file from Hugging Face (e.g., `Meta-Llama-3.1-8B-Instruct-Q4_K_M.gguf`).

Start the server:

```sh
llama-server \
  --model models/Meta-Llama-3.1-8B-Instruct-Q4_K_M.gguf \
  --port 8080 \
  --ctx-size 8192
```

### pgmoneta-mcp.conf Example

```ini
[llm]
provider = llama.cpp
endpoint = http://localhost:8080
model = Meta-Llama-3.1-8B-Instruct-Q4_K_M.gguf
max_tool_rounds = 10
```

## RamaLama

[RamaLama](https://ramalama.ai) is an open-source command-line interface and unified AI gateway that simplifies the deployment and inference of AI models using containerization (Podman or Docker).

### Basic Setup (Rocky Linux 10)

It is available natively on RPM-based distributions:

```sh
dnf install ramalama
```

RamaLama handles pulling models automatically. Start the server for the recommended model:

```sh
ramalama serve granite-code
```

The default endpoint is `http://localhost:8080`.

### pgmoneta-mcp.conf Example

```ini
[llm]
provider = ramalama
endpoint = http://localhost:8080
model = granite-code
max_tool_rounds = 10
```

## vLLM

[vLLM](https://github.com/vllm-project/vllm) is a high-throughput and memory-efficient engine for LLMs that natively exposes an OpenAI-compatible API.

### Install

Install vLLM via pip (a virtual environment is recommended):

```
pip install vllm
```

### Start the server

vLLM automatically downloads standard Safetensor models from Hugging Face:

```
python -m vllm.entrypoints.openai.api_server \
  --model ibm-granite/granite-3.0-8b-instruct \
  --port 8000
```

Verify it is running:

```
curl http://localhost:8000/v1/models
```

### pgmoneta-mcp.conf Example

```ini
[llm]
provider = vllm
endpoint = http://localhost:8000
model = ibm-granite/granite-3.0-8b-instruct
max_tool_rounds = 10
```

### Configuration properties

| Property | Default | Required | Description |
| :------- | :------ | :------- | :---------- |
| provider |  | Yes | The LLM provider backend (`ollama`, `llama.cpp`, `ramalama` or `vllm`) |
| endpoint |  | Yes | The URL of the LLM inference server |
| model |  | Yes | The model name to use for inference |
| max_tool_rounds | 10 | No | Maximum tool-calling iterations per user prompt |

## Quick verification

1. Confirm your LLM server is running:

For **Ollama**:
```sh
curl http://localhost:11434/
```

For **llama.cpp**:
```sh
curl http://localhost:8080/health
```

For **RamaLama**:
```sh
curl http://localhost:8080/v1/models
```

For **vLLM**:
```sh
curl http://localhost:8000/v1/models
```

2. Start pgmoneta MCP with your config file:

```sh
pgmoneta-mcp-server -c pgmoneta-mcp.conf -u pgmoneta-mcp-users.conf
```

3. From your MCP client, ask for backup information to verify end-to-end setup.