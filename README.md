# pgmoneta MCP

[![SafeSkill 82/100](https://img.shields.io/badge/SafeSkill-82%2F100_Passes%20with%20Notes-yellow)](https://safeskill.dev/scan/pgmoneta-pgmoneta-mcp)

<p align="center">
  <img src="doc/images/logo-reversed-transparent.svg" alt="pgmoneta_mcp logo" width="256" />
</p>

**pgmoneta MCP** is the official [Model Context Protocol](https://modelcontextprotocol.io/docs/getting-started/intro) server built
for [pgmoneta](https://pgmoneta.github.io/), a backup / restore solution for [PostgreSQL](https://www.postgresql.org).

## Overview

**pgmoneta MCP** is built upon [rmcp](https://docs.rs/rmcp/latest/rmcp/).

It uses [SCRAM-SHA-256](https://datatracker.ietf.org/doc/html/rfc7677) to authenticate with pgmoneta server.

User management is done with the administration tool called `pgmoneta-mcp-admin`.

## Local LLM Support

**pgmoneta MCP** supports local installation of Open Source LLM models that can run without network access.

LLMs

* [Ollama](https://ollama.com)
* [llama.cpp](https://github.com/ggml-org/llama.cpp)

Models

* [Llama](https://ollama.com/library/llama3.1)
* [Qwen](https://ollama.com/library/qwen2.5)
* [Kimi](https://ollama.com/library/kimi-k2)
* [mistral](https://huggingface.co/mistralai/Mistral-7B-v0.3)
* [mixtral](https://huggingface.co/mistralai/Mixtral-8x7B-Instruct-v0.1)

See [doc/LOCAL_LLM.md](doc/LOCAL_LLM.md) for installation and configuration instructions.

## Compiling the source

**pgmoneta** requires

* [rust](https://rust-lang.org/)
* [cargo](https://rust-lang.org/)
* [rst2man](https://docutils.sourceforge.io/)
* [pandoc](https://pandoc.org/)
* [texlive](https://www.tug.org/texlive/)

```sh
dnf install rust rust-analyzer rustfmt rust-src rust-std-static cargo
```

### Release build

The following commands will install **pgmoneta MCP** in the `/usr/local` hierarchy.

```sh
git clone https://github.com/pgmoneta/pgmoneta_mcp.git
cd pgmoneta_mcp
cargo build --release
sudo cargo install --root /usr/local/
```

### Debug build

The following commands will create a `DEBUG` version of **pgmoneta MCP**.

```sh
git clone https://github.com/pgmoneta/pgmoneta_mcp.git
cd pgmoneta_mcp
cargo build
cd target/debug
```

## Contributing

Contributions to **pgmoneta** are managed on [GitHub.com](https://github.com/pgmoneta/pgmoneta_mcp/)

* [Ask a question](https://github.com/pgmoneta/pgmoneta_mcp/discussions)
* [Raise an issue](https://github.com/pgmoneta/pgmoneta_mcp/issues)
* [Feature request](https://github.com/pgmoneta/pgmoneta_mcp/issues)
* [Code submission](https://github.com/pgmoneta/pgmoneta_mcp/pulls)

Contributions are most welcome !

Please, consult our [Code of Conduct](./CODE_OF_CONDUCT.md) policies for interacting in our
community.

Consider giving the project a [star](https://github.com/pgmoneta/pgmoneta_mcp/stargazers) on
[GitHub](https://github.com/pgmoneta/pgmoneta_mcp/) if you find it useful. And, feel free to follow
the project on [X](https://x.com/pgmoneta/) as well.


## License

[GNU General Public License v3.0](https://www.gnu.org/licenses/gpl-3.0.en.html)
