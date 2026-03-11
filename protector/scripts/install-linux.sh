#!/usr/bin/env bash
set -euo pipefail
REPO="${REPO:-https://github.com/tbagzhao668/OpenclawFW.git}"
DIR="${DIR:-/opt/openclaw-protector}"
TMP="$(mktemp -d)"
OS=linux
UNAME_ARCH="$(uname -m)"
case "$UNAME_ARCH" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  armv7l|armv7) ARCH=armv7 ;;
  *) ARCH=amd64 ;;
esac
# Derive releases base like https://github.com/OWNER/REPO/releases/latest/download
BASE="${REPO%.git}"
TAG_PATH="${TAG:-latest}"
ASSET="consent-agent-${OS}-${ARCH}"
URL="$BASE/releases/$TAG_PATH/download/$ASSET"

install_binary() {
  sudo mkdir -p "$DIR"
  sudo cp "$1" "$DIR/consent-agent"
  sudo chown root:root "$DIR/consent-agent"
  sudo chmod 755 "$DIR/consent-agent"
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

sudo tee /etc/systemd/system/oc-protector.service >/dev/null <<EOF
[Unit]
Description=OpenClaw Protector Agent
After=network-online.target
[Service]
ExecStart=$DIR/consent-agent
Restart=on-failure
User=root
WorkingDirectory=$DIR
[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now oc-protector.service
echo "http://127.0.0.1:48231/"
