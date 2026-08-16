#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV="${PROJECT_ROOT}/.venv"
PYTHON="${PYTHON:-python3}"

command -v git >/dev/null || { echo "Git is required and was not found on PATH." >&2; exit 1; }
command -v "${PYTHON}" >/dev/null || { echo "Python 3.10 or newer is required." >&2; exit 1; }

if [[ ! -x "${VENV}/bin/python" ]]; then
  "${PYTHON}" -m venv "${VENV}"
fi
"${VENV}/bin/python" -m pip install --upgrade pip
"${VENV}/bin/python" -m pip install --upgrade platformio esptool
git -C "${PROJECT_ROOT}" submodule update --init --recursive

if [[ "${INSTALL_VSCODE_EXTENSION:-0}" == "1" ]]; then
  command -v code >/dev/null || { echo "VS Code CLI 'code' was not found." >&2; exit 1; }
  code --install-extension platformio.platformio-ide
fi

echo "Setup complete. Use ${VENV}/bin/python -m platformio for builds."
echo "Set INSTALL_VSCODE_EXTENSION=1 before rerunning to install the VS Code extension."
