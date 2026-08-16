#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${PROJECT_ROOT}/.venv/bin/python"
[[ -x "${PYTHON}" ]] || PYTHON="${PYTHON_BIN:-python3}"
TARGET=""
PORT=""
BAUD=115200
UPLOAD=0
MONITOR=0
NO_BUILD=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target) TARGET="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --baud) BAUD="$2"; shift 2 ;;
    --upload) UPLOAD=1; shift ;;
    --monitor) MONITOR=1; shift ;;
    --no-build) NO_BUILD=1; shift ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

[[ -n "${TARGET}" ]] || { echo "--target is required." >&2; exit 2; }
if [[ "${UPLOAD}" == 1 || "${MONITOR}" == 1 ]] && [[ -z "${PORT}" ]]; then
  echo "--port is required with --upload or --monitor." >&2
  exit 2
fi

cd "${PROJECT_ROOT}"
if [[ "${NO_BUILD}" == 0 ]]; then "${PYTHON}" -m platformio run -e "${TARGET}"; fi
if [[ "${UPLOAD}" == 1 ]]; then "${PYTHON}" scripts/flash_esptool.py --target "${TARGET}" --port "${PORT}" --no-build; fi
if [[ "${MONITOR}" == 1 ]]; then "${PYTHON}" -m platformio device monitor --port "${PORT}" --baud "${BAUD}"; fi
