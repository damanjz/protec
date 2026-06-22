#!/usr/bin/env bash
# Registers the protec-host native-messaging host for Chromium browsers + Firefox
# on macOS. macOS equivalent of register-host.ps1 (keep the two in sync: same host
# name "dev.protec.host", same allowed_origins/allowed_extensions contract).
#
# Usage:
#   ./register-host-macos.sh /absolute/path/to/protec-host [CHROMIUM_EXT_ID] [FIREFOX_EXT_ID]
#
# macOS writes the manifest JSON directly into each browser's NativeMessagingHosts
# directory (there is no registry as on Windows).
set -euo pipefail

HOST_NAME="dev.protec.host"
HOST_BIN="${1:?usage: register-host-macos.sh /absolute/path/to/protec-host [chromium-ext-id] [firefox-ext-id]}"
CHROMIUM_EXT_ID="${2:-REPLACE_WITH_CHROMIUM_EXTENSION_ID}"
FIREFOX_EXT_ID="${3:-protec@local}"

if [ ! -x "$HOST_BIN" ]; then
  echo "warning: host binary '$HOST_BIN' is not executable or does not exist" >&2
fi

APPSUP="$HOME/Library/Application Support"

# Chromium-family browsers use allowed_origins = ["chrome-extension://<id>/"].
chromium_manifest() {
  cat <<JSON
{
  "name": "${HOST_NAME}",
  "description": "Protec native messaging host",
  "path": "${HOST_BIN}",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://${CHROMIUM_EXT_ID}/"]
}
JSON
}

# Firefox uses allowed_extensions = ["<ext-id>"].
firefox_manifest() {
  cat <<JSON
{
  "name": "${HOST_NAME}",
  "description": "Protec native messaging host",
  "path": "${HOST_BIN}",
  "type": "stdio",
  "allowed_extensions": ["${FIREFOX_EXT_ID}"]
}
JSON
}

# Chromium-family NativeMessagingHosts directories.
CHROMIUM_DIRS=(
  "$APPSUP/Google/Chrome/NativeMessagingHosts"
  "$APPSUP/Chromium/NativeMessagingHosts"
  "$APPSUP/Microsoft Edge/NativeMessagingHosts"
  "$APPSUP/BraveSoftware/Brave-Browser/NativeMessagingHosts"
)
for d in "${CHROMIUM_DIRS[@]}"; do
  mkdir -p "$d"
  chromium_manifest > "$d/${HOST_NAME}.json"
  echo "Wrote ${d}/${HOST_NAME}.json"
done

# Firefox.
FF_DIR="$APPSUP/Mozilla/NativeMessagingHosts"
mkdir -p "$FF_DIR"
firefox_manifest > "$FF_DIR/${HOST_NAME}.json"
echo "Wrote ${FF_DIR}/${HOST_NAME}.json"

echo "Registered protec-host for Chromium-family browsers and Firefox on macOS."
