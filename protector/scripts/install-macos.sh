#!/usr/bin/env bash
set -euo pipefail
REPO="${REPO:-https://github.com/tbagzhao668/OpenclawFW.git}"
DIR="${DIR:-$HOME/openclaw-protector}"
TMP="$(mktemp -d)"
OS=darwin
UNAME_ARCH="$(uname -m)"
case "$UNAME_ARCH" in
  x86_64|amd64) ARCH=amd64 ;;
  arm64) ARCH=arm64 ;;
  *) ARCH=arm64 ;;
esac
BASE="${REPO%.git}"
TAG_PATH="${TAG:-latest}"
ASSET="consent-agent-${OS}-${ARCH}"
URL="$BASE/releases/$TAG_PATH/download/$ASSET"

install_binary() {
  mkdir -p "$DIR"
  cp "$1" "$DIR/consent-agent"
  chmod 755 "$DIR/consent-agent"
}

echo "Attempting to download release asset: $URL"
if command -v curl >/dev/null 2>&1 && curl -fsSL -o "$TMP/$ASSET" "$URL" ; then
  install_binary "$TMP/$ASSET"
else
  echo "Release asset unavailable; falling back to local build from source"
  git clone --depth=1 "$REPO" "$TMP"
  cd "$TMP/protector/cmd/agent"
  go build -o consent-agent
  install_binary "consent-agent"
fi
PLIST="$HOME/Library/LaunchAgents/ai.openclaw.protector.plist"
cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>ai.openclaw.protector</string>
  <key>ProgramArguments</key>
  <array>
    <string>$DIR/consent-agent</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>WorkingDirectory</key><string>$DIR</string>
  <key>StandardOutPath</key><string>/tmp/oc-protector.out</string>
  <key>StandardErrorPath</key><string>/tmp/oc-protector.err</string>
</dict>
</plist>
EOF
launchctl unload "$PLIST" >/dev/null 2>&1 || true
launchctl load "$PLIST"
launchctl start ai.openclaw.protector
echo "http://127.0.0.1:48231/"
