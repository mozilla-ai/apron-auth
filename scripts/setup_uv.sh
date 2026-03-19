#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

LOCAL_BIN="${LOCAL_BIN:-$HOME/.local/bin}"

mkdir -p "$LOCAL_BIN"
if [[ ":$PATH:" != *":$LOCAL_BIN:"* ]]; then
  export PATH="$LOCAL_BIN:$PATH"
fi

VENV_DIR=".venv"

if ! command -v uv &>/dev/null; then
  echo "uv not found – installing to $LOCAL_BIN"
  curl -fsSL https://astral.sh/uv/install.sh | UV_INSTALL_DIR="$LOCAL_BIN" sh
else
  current=$(uv --version | awk '{print $2}')
  echo "Found uv v$current"
  if command -v jq &>/dev/null; then
    latest=$(curl -fsS https://api.github.com/repos/astral-sh/uv/releases/latest \
             | jq -r .tag_name)
    if [[ "$current" != "$latest" ]]; then
      echo "Updating uv: $current → $latest"
      uv self update
    fi
  fi
fi

echo "Bootstrapping root .venv in folder $VENV_DIR"
uv venv "$VENV_DIR"
uv sync --group dev --active

echo "Done! Root environment is ready in: $VENV_DIR"

echo "Installing pre-commit hooks"
uv run pre-commit install

if [[ ":$PATH:" != *":$LOCAL_BIN:"* ]]; then
  echo "Note: added $LOCAL_BIN to PATH for this session."
  echo "To make it permanent, add to your shell profile:"
  echo "  export PATH=\"$LOCAL_BIN:\$PATH\""
fi
