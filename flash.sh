#!/usr/bin/env bash
# Flash over the board's native USB Serial/JTAG port (the XIAO has no UART bridge chip).
# Needs sudo only because /dev/ttyACM0 is root:dialout and this user is not in dialout.
set -euo pipefail
cd "$(dirname "$0")"
PORT="${1:-/dev/ttyACM0}"

sudo env IDF_PATH="${IDF_PATH:-$HOME/esp/esp-idf}" \
         IDF_TOOLS_PATH="${IDF_TOOLS_PATH:-$HOME/.espressif}" \
         IDF_PYTHON_ENV_PATH="${IDF_PYTHON_ENV_PATH:-$HOME/.espressif/python_env/idf5.4_py3.11_env}" \
     bash -c '. "$IDF_PATH/export.sh" >/dev/null 2>&1 && idf.py -p '"$PORT"' flash'
