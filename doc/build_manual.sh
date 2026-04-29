#!/bin/bash
set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
readonly MANUAL_DIR="$SCRIPT_DIR/manual/en"
readonly OUTPUT_DIR="$PROJECT_ROOT/target/doc"
readonly PDF_OUTPUT="$OUTPUT_DIR/pgmoneta-mcp-en.pdf"
readonly HTML_OUTPUT="$OUTPUT_DIR/pgmoneta-mcp-en.html"
readonly RESOURCE_PATH="$SCRIPT_DIR:$MANUAL_DIR"

if ! command -v pandoc >/dev/null 2>&1; then
    echo "Error: pandoc is required but was not found in PATH." >&2
    exit 1
fi

if command -v xelatex >/dev/null 2>&1; then
    readonly PDF_ENGINE="xelatex"
elif command -v lualatex >/dev/null 2>&1; then
    readonly PDF_ENGINE="lualatex"
else
    echo "Error: xelatex or lualatex is required for PDF output." >&2
    exit 1
fi

shopt -s nullglob
manual_sources=("$MANUAL_DIR"/??-*.md)
shopt -u nullglob

if [[ ${#manual_sources[@]} -eq 0 ]]; then
    echo "Error: no manual sources found in $MANUAL_DIR matching ??-*.md" >&2
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo "Generating PDF manual: $PDF_OUTPUT"
(
  cd "$SCRIPT_DIR"
  pandoc \
    -o "$PDF_OUTPUT" \
    --from markdown \
    --resource-path="$RESOURCE_PATH" \
    --template eisvogel \
    --listings \
    --pdf-engine="$PDF_ENGINE" \
    -N \
    --toc \
    "${manual_sources[@]}"
)

echo "Generating HTML manual: $HTML_OUTPUT"
(
  cd "$SCRIPT_DIR"
  pandoc \
    -o "$HTML_OUTPUT" \
    -s \
    -f markdown-smart \
    --resource-path="$RESOURCE_PATH" \
    -N \
    --toc \
    -t html5 \
    "${manual_sources[@]}"
)

echo "Manual generated:"
echo "  $PDF_OUTPUT"
echo "  $HTML_OUTPUT"
