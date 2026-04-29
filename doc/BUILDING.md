# Building

This document describes how to build the project binaries, API documentation, and the manual.

## Build the project

From the repository root:

```bash
cargo build
```

To build with optimizations:

```bash
cargo build --release
```

## Build the API documentation

From the repository root:

```bash
cargo doc --no-deps
```

The generated API docs are written to:

```text
target/doc/
```

## Build the manual (PDF + HTML)

The manual source files are read from:

```text
doc/manual/en/??-*.md
```

### Prerequisites

- [Pandoc](https://pandoc.org)
- Eisvogel template available to [Pandoc](https://pandoc.org) (`--template eisvogel`)
- A Unicode-capable [LaTeX](https://www.tug.org/texlive/) engine supported by your Pandoc setup, such as `xelatex` or `lualatex` (for PDF output)

```sh
dnf install pandoc texlive-scheme-basic \
            'tex(footnote.sty)' 'tex(footnotebackref.sty)' \
            'tex(pagecolor.sty)' 'tex(hardwrap.sty)' \
            'tex(mdframed.sty)' 'tex(sourcesanspro.sty)' \
            'tex(ly1enc.def)' 'tex(sourcecodepro.sty)' \
            'tex(titling.sty)' 'tex(csquotes.sty)' \
            'tex(zref-abspage.sty)' 'tex(needspace.sty)'
```

You will need the `Eisvogel` template as well which you can install through

```sh
wget https://github.com/Wandmalfarbe/pandoc-latex-template/releases/download/v3.4.0/Eisvogel-3.4.0.tar.gz
tar -xzf Eisvogel-3.4.0.tar.gz
mkdir -p ~/.local/share/pandoc/templates
mv Eisvogel-3.4.0/eisvogel.latex ~/.local/share/pandoc/templates/
```

where `$HOME` is your home directory.

### Build command

From the repository root:

```bash
./doc/build_manual.sh
```

The generated manual files are written to:

```text
target/doc/pgmoneta-mcp-en.pdf
target/doc/pgmoneta-mcp-en.html
```
