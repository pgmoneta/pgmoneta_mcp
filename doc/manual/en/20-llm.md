\newpage

# Local LLM

**pgmoneta_mcp** can be used together with a local large language model (LLM) so that
users can explore pgmoneta backups in natural language without sending prompts or
backup metadata to a cloud service.

## What is a local LLM?

A local LLM is an artificial intelligence model that runs entirely on your own
hardware. Unlike cloud-based services, all data processing, storage, and
inference stays within your private infrastructure. This ensures privacy and
data sovereignty while providing natural language capabilities for database
management.

## Functionality

The local LLM integration is built around three parts:

* The **pgmoneta MCP server**, which exposes pgmoneta operations as MCP tools
* A local **LLM runtime**, which hosts a tool-capable model
* The **agent** layer, which sends prompts to the model, executes requested tools,
  and returns a final answer

The overall flow looks like this:

``` text
User prompt
    |
    v
Local LLM runtime (Ollama, RamaLama, vLLM or llama.cpp)
    |
    v
pgmoneta_mcp tools
    |
    v
pgmoneta
```

## Configuration

Add an `[llm]` section to your `pgmoneta-mcp.conf` file to configure the runtime.

### Configuration properties

| Property | Default | Required | Description |
| :------- | :------ | :------- | :---------- |
| provider |  | Yes | The LLM provider backend (`ollama`, `llama.cpp`, `vLLM` or `ramalama`) |
| endpoint |  | Yes | The URL of the LLM inference server |
| model |  | Yes | The explicit model name to use for inference |
| max_tool_rounds | 10 | No | Maximum tool-calling iterations per user prompt |

## Comparison

When choosing a local runtime for **pgmoneta_mcp**, consider the following trade-offs
between ease of use and granular control.

### Runtime comparison

| Feature | Ollama | RamaLama | llama.cpp | vLLM |
| :--- | :--- | :--- | :--- | :--- |
| **Installation** | Single binary / installer | System package (dnf/pip) | Download or build binary | Python package (pip) |
| **Model Management** | Built-in CLI (`pull`, `list`) | Automatic (OCI/HF registry) | Manual download of `.gguf` files | Auto-downloads Safetensors |
| **Ease of Use** | High (recommended for beginners) | High (container-based) | Advanced (manual configuration) | Intermediate |
| **Control** | Automatic hardware detection | Container-native isolation | Granular threading/GPU/RAM control | High-throughput optimizations |
| **Performance** | Excellent (balanced) | Excellent (flexibility) | Maximum (optimized for specific hardware) | Production-grade throughput |

### Pros and Cons

**Ollama**

**Pros:**

* **Simple installation**: A single binary or system package — no compilation required.
* **Built-in model management**: Download, list, and switch models using familiar CLI commands (`ollama pull`, `ollama list`, `ollama run`), similar to how Docker manages images.
* **Automatic hardware detection**: Detects your CPU, RAM, and GPU automatically and selects optimal defaults.
* **Runs as a persistent service**: Works as a background daemon, so it survives terminal sessions and integrates cleanly into system startup.
* **Large ecosystem**: Well-documented with an active community and many supported models listed at [ollama.com/library](https://ollama.com/library).

**Cons:**

* **Less hardware control**: You cannot easily override the number of GPU layers, thread counts, or memory layout without advanced configuration.
* **Abstraction layer overhead**: Ollama adds a management layer on top of llama.cpp. For most users this is beneficial, but for advanced hardware tuning it can be limiting.

**llama.cpp**

**Pros:**

* **Granular hardware control**: Expose and tune parameters like `--n-gpu-layers` (how many layers to offload to GPU), `--threads` (CPU thread count), and `--ctx-size` (context window size) to match your exact hardware.
* **Portable and scriptable**: `llama-server` is a standalone binary that can be embedded in shell scripts, Docker containers, or automation pipelines without a daemon.
* **Native OpenAI API**: Exposes the standard `/v1/chat/completions` endpoint directly, making it compatible with any OpenAI-compatible client.
* **Widest quantization support**: Supports every quantization format (`Q2_K`, `Q4_K_M`, `Q8_0`, `IQ3_M` etc.), giving full control over the size vs. quality trade-off.

**Cons:**

* **No built-in model registry**: You must manually find, download, and organize `.gguf` model files from sources like Hugging Face.
* **No model management**: No built-in equivalent of `ollama list` or `ollama pull`. You manage model files and versions yourself.
* **Manual startup**: Requires a precise launch command each time (`--model`, `--port`, `--ctx-size`, etc.), with no automatic restart on failure.

**vLLM**

**Pros:**

* **Production-grade throughput**: Replaces standard sequence processing with PagedAttention, allowing for massive batched throughput.
* **OpenAI-compatible**: Exposes a standard `/v1/chat/completions` API out of the box.
* **Auto-downloads weights**: Transparently pulls industry-standard Safetensor weights from Hugging Face when you specify a model ID, removing the need for `gguf` conversion or manual downloads.

**Cons:**

* **High resource overhead**: Optimized for serving multiple requests simultaneously, rendering its baseline idle CPU/VRAM footprint larger than Ollama or llama.cpp.
* **Python dependency stack**: Installation pulls down heavy dependencies (like PyTorch and CUDA bindings) unless managed firmly via virtual environments or Docker.
* **Lacks low-end quantization**: Not designed for hyper-compressed formats (like `Q2_K`) frequently used to squeeze models onto low-end hardware.

**RamaLama**

**Pros:**

* **Container-native isolation**: Provides excellent reproducibility and environment security through Podman/Docker.
* **Unified AI gateway**: Can pull models from any OCI-compliant registry or Hugging Face.
* **Inference flexibility**: Supports multiple backends (like `vLLM` or `MLX`) through a single interface.
* **Standardized**: Built from the ground up to be OpenAI-compatible.

**Cons:**

* **External dependency**: Requires a container engine to be installed and running.
* **Container knowledge**: Slightly steeper learning curve for users unfamiliar with containers.

## Model Selection

When choosing an LLM for **pgmoneta_mcp**, keep these key concepts in mind regardless of which provider you choose:

1. **Instruct vs. Base**: You must use a model fine-tuned for instruction following or chat (usually labeled `Instruct` or `Chat`). Base models are not trained to follow instructions and will fail at tool calling.
2. **Hardware Limits**: The model's listed file size indicates the *minimum* RAM needed simply to load its weights. Actual runtime usage will be 20-30% higher because the runtime allocates memory for context caching and inference buffers.

### Understanding model names

Whether you are pulling a model via Ollama or RamaLama, or downloading a `.gguf` file for `llama.cpp`, the model name usually encodes its size and compression level:

``` text
Qwen2.5-7B-Instruct-Q4_K_M
       ^^^           ^^^^^^
        |               |
        |               +-- Quantization level (Qy)
        +-- Parameter count (xB)
```

**Parameter count (`xB`)**

The `xB` part (e.g. `3B`, `7B`, `8B`) stands for *billions of parameters* — the number of internal connections in the neural network. A larger model uses more disk space and RAM. In return, you get better **tool calling accuracy** — the model is more likely to pick the right tool, pass correct arguments, and reason correctly about the results.

For **pgmoneta_mcp**, tool calling is what matters most. A model that is too small may:
- Call the wrong tool or skip tools entirely
- Pass incorrect arguments (wrong server name, wrong backup ID)
- Fail to follow multi-step instructions

Start with a `7B` or `8B` model as a baseline. If the model repeatedly calls wrong tools or produces incorrect results, move to a larger model. A `3B` model needs roughly half the RAM of a `7B` model, but at a cost in reasoning quality.

**Quantization level (`Qy`)**

Models are compressed ("quantized") to reduce memory usage. The `Q` suffix indicates the compression level. `Q4_K_M` (4-bit quantization) is the recommended starting point for most setups — it uses roughly half the RAM of an uncompressed model with only a minor drop in reasoning quality.

### Model Compatibility Matrix

The model must support **tool calling** (function calling) to work with pgmoneta MCP tools.

| Model | Size | RAM Needed | Ollama | RamaLama | llama.cpp | vLLM | Notes |
| :---- | :--- | :--------- | :----- | :------- | :-------- | :--- | :---- |
| `granite-code` | ~5.0 GB | ~8 GB | Yes | Yes | Yes (GGUF) | Yes | **Recommended**. Built for coding and tool-calling |
| `llama3.1:8b` | ~4.7 GB | ~8 GB | Yes | Yes | Yes (GGUF) | Yes | Best balance of capability and size |
| `llama3.2:3b` | ~2.0 GB | ~4 GB | Yes | Yes | Yes (GGUF) | Yes | Lightweight option for limited hardware |
| `qwen2.5:7b` | ~4.7 GB | ~8 GB | Yes | Yes | Yes (GGUF) | Yes | Excellent tool calling capabilities |
| `mistral:7b` | ~4.1 GB | ~8 GB | Yes | Yes | Yes (GGUF) | Yes | Strong performance for open-source models |

Examples of provider-specific model names can be found in the Ollama, RamaLama, llama.cpp, and vLLM sections.

## Next step

The following sections document the recommended local runtimes: **Ollama**, **RamaLama**, **llama.cpp**, and **vLLM**, including installation, model setup, and configuration.