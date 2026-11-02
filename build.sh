#!/usr/bin/env bash
# Build with a native (non-Docker) ESP-IDF v5.4.1 install.
# Override IDF_PATH / IDF_TOOLS_PATH / IDF_PYTHON_ENV_PATH if yours live elsewhere.
#
# Usage:
#   ./build.sh                        # ESP32-S3 devkit, 16MB flash
#   ./build.sh esp32                  # classic ESP32, no PSRAM
#   ./build.sh esp32s3 xiao-s3        # Seeed XIAO ESP32-S3 (8MB flash, native USB)
set -euo pipefail
cd "$(dirname "$0")"

CHIP="${1:-esp32s3}"
PROFILE="${2:-}"

export IDF_PATH="${IDF_PATH:-$HOME/esp/esp-idf}"
export IDF_TOOLS_PATH="${IDF_TOOLS_PATH:-$HOME/.espressif}"
export IDF_PYTHON_ENV_PATH="${IDF_PYTHON_ENV_PATH:-$HOME/.espressif/python_env/idf5.4_py3.11_env}"
[ -f "$IDF_PATH/export.sh" ] || { echo "ESP-IDF not found at $IDF_PATH (set IDF_PATH)"; exit 1; }
# shellcheck disable=SC1091
. "$IDF_PATH/export.sh" >/dev/null

export GADGET_PROFILE="$PROFILE"
[ -n "$PROFILE" ] && echo "board profile: $PROFILE"

# sdkconfig is generated once and does NOT re-read the defaults afterwards, so a newly
# written credentials file would be silently ignored. Regenerate when it is newer.
if [ -f sdkconfig ] && [ -f sdkconfig.credentials ] && \
   [ sdkconfig.credentials -nt sdkconfig ]; then
  echo "credentials changed, regenerating sdkconfig"
  rm -f sdkconfig
fi

if [ ! -f sdkconfig ]; then
  idf.py set-target "$CHIP"
fi
idf.py build
