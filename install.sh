#!/bin/bash
# Dockfolio — One-Command Install
# Usage: curl -fsSL https://raw.githubusercontent.com/dockfolio/dockfolio/master/install.sh | bash
set -euo pipefail

INSTALL_DIR="${DOCKFOLIO_DIR:-$HOME/dockfolio}"
PORT="${APP_PORT:-9091}"
REPO="https://raw.githubusercontent.com/dockfolio/dockfolio/master"

echo ""
echo "  Dockfolio — Install"
echo "  ==================="
echo ""

# Check prerequisites
if ! command -v docker &>/dev/null; then
  echo "Error: Docker is not installed."
  echo "Install Docker first: https://docs.docker.com/engine/install/"
  exit 1
fi

if ! docker compose version &>/dev/null && ! command -v docker-compose &>/dev/null; then
  echo "Error: Docker Compose is not installed."
  echo "Install it: https://docs.docker.com/compose/install/"
  exit 1
fi

if ! docker info &>/dev/null 2>&1; then
  echo "Error: Cannot connect to Docker. Is the Docker daemon running?"
  echo "Try: sudo systemctl start docker"
  exit 1
fi

echo "[1/4] Creating directory: $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

echo "[2/4] Downloading configuration..."
curl -fsSL "$REPO/docker-compose.prod.yml" -o docker-compose.yml

# Create minimal config if it doesn't exist
if [ ! -f config.yml ]; then
  cat > config.yml << 'EOF'
# Dockfolio Configuration
# Apps are auto-discovered from Docker, but you can also define them here.
# Add apps via the Settings panel in the dashboard UI.
apps: []
EOF
fi

# Create .env if it doesn't exist
if [ ! -f .env ]; then
  cat > .env << EOF
# Dockfolio Environment
APP_PORT=$PORT

# Optional: Telegram notifications for auto-healing alerts
# TELEGRAM_BOT_TOKEN=
# TELEGRAM_CHAT_ID=

# Optional: Plausible Analytics integration
# PLAUSIBLE_URL=http://your-plausible:8000
# PLAUSIBLE_API_KEY=
EOF
fi

echo "[3/4] Starting Dockfolio..."
docker compose up -d

echo "[4/4] Waiting for health check..."
for i in $(seq 1 30); do
  if curl -sf "http://127.0.0.1:$PORT/health" > /dev/null 2>&1; then
    echo ""
    echo "  Dockfolio is running!"
    echo ""
    echo "  Dashboard:  http://$(hostname -I 2>/dev/null | awk '{print $1}' || echo 'localhost'):$PORT"
    echo "  Local:      http://127.0.0.1:$PORT"
    echo ""
    echo "  Open the URL above to create your admin account."
    echo "  Then use Settings to add your Docker apps."
    echo ""
    echo "  Config:     $INSTALL_DIR/config.yml"
    echo "  Data:       Docker volume 'dockfolio-data'"
    echo ""
    exit 0
  fi
  sleep 1
done

echo ""
echo "Warning: Health check timed out. Check logs with:"
echo "  docker logs dockfolio"
echo ""
