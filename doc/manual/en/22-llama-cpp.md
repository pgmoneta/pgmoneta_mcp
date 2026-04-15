
## llama.cpp

[llama.cpp](https://github.com/ggml-org/llama.cpp) is a high-performance C++ library for running LLMs locally. It allows granular control over GPU offloading, context windows, and threading, making it suitable for users who require direct control over hardware and model configuration.

Using `llama.cpp` with `pgmoneta-mcp` requires:

1. Manually downloading model files (`.gguf`).
2. Running the `llama-server` process yourself.

### Install

To use `llama.cpp`, you need to download or build the `llama-server` binary.

Instructions can be found on the [llama.cpp releases page](https://github.com/ggml-org/llama.cpp/releases).

### Download models

`llama.cpp` does not have a built-in model registry. You must find, evaluate, and download a `.gguf` model file manually.

### Storage Management

Download `.gguf` files directly to your preferred high-capacity drive (e.g., `/mnt/ai/models/`) to avoid disk exhaustion.

**Step 1: Find a model on Hugging Face**

Go to [huggingface.co](https://huggingface.co/) and search for a model name followed by `GGUF`, for example:

```
Qwen2.5-7B-Instruct GGUF
```

Look for repositories from trusted authors such as `bartowski` or the original model author.

**Step 2: Choose your model**

As explained in the general LLM chapter (`20-llm.md`), `.gguf` filenames encode the parameter count (`xB`) and quantization level (`Q`). `Q4_K_M` is the recommended balance of speed, size, and reasoning quality.

If you have extremely limited RAM, you may choose `Q2_K`, or `Q8_0` for near-original quality.

For **pgmoneta_mcp**, the following specific files are suitable choices:

| Model file | Size | RAM needed | Notes |
| :--------- | :--- | :--------- | :---- |
| `Qwen2.5-7B-Instruct-Q4_K_M.gguf` | ~4.7 GB | ~8 GB | Strong tool calling accuracy |
| `Qwen2.5-3B-Instruct-Q4_K_M.gguf` | ~1.9 GB | ~4 GB | Lower hardware requirement, some accuracy trade-off |
| `Meta-Llama-3.1-8B-Instruct-Q4_K_M.gguf` | ~4.7 GB | ~8 GB | Widely used, good general reasoning |

**Step 3: Download the file**

Use the Hugging Face web interface or the CLI below for our three standard setups:

**Small setup** (Laptop friendly; `Llama-3.2-3B`):
``` sh
wget https://huggingface.co/bartowski/Llama-3.2-3B-Instruct-GGUF/resolve/main/Llama-3.2-3B-Instruct-Q4_K_M.gguf -P /mnt/ai/models/
```

**Best setup** (Recommended; `granite-3.0-8b`):
``` sh
wget https://huggingface.co/bartowski/granite-3.0-8b-instruct-GGUF/resolve/main/granite-3.0-8b-instruct-Q4_K_M.gguf -P /mnt/ai/models/
```

**Full setup** (Workstation only; `Meta-Llama-3.1-70B`):
``` sh
wget https://huggingface.co/bartowski/Meta-Llama-3.1-70B-Instruct-GGUF/resolve/main/Meta-Llama-3.1-70B-Instruct-Q4_K_M.gguf -P /mnt/ai/models/
```

### Start the server

Start `llama-server` with your downloaded model:

``` sh
llama-server \
  --model /mnt/ai/models/granite-3.0-8b-instruct-Q4_K_M.gguf \
  --port 8080 \
  --ctx-size 8192
```

The default endpoint will be `http://localhost:8080`.

### Configure pgmoneta_mcp

Add or update the `[llm]` section in `pgmoneta-mcp.conf`:

``` ini
[llm]
provider = llama.cpp
endpoint = http://localhost:8080
model = granite-3.0-8b-instruct-Q4_K_M
max_tool_rounds = 10
```

### Quick verification

Confirm the server is running:

``` sh
curl http://localhost:8080/health
```

Start **pgmoneta_mcp**:

``` sh
pgmoneta-mcp-server -c pgmoneta-mcp.conf -u pgmoneta-mcp-users.conf
```

Open your MCP client and ask a question about your backups to verify end-to-end setup.


### Using llama.cpp Web UI


1. Use the URL of the llama server `http://localhost:8080` in your browser. If the page is already open, refresh it.
2. Open the Web UI settings, select `MCP`, click `Add New Server`, and enter the pgmoneta-mcp URL. If a pgmoneta-mcp server entry exists, delete it and add it again.
