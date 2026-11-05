#!/usr/bin/env bash
# Self-deploy script run ON the server.
# Pulls the latest main; if there are new commits, reinstalls deps and
# restarts the systemd service. Does nothing when already up to date.
set -euo pipefail

REPO_DIR="/home/ubuntu/backend"
BRANCH="main"
SERVICE="ibalance-backend"

cd "$REPO_DIR"

git fetch --quiet origin "$BRANCH"

LOCAL=$(git rev-parse HEAD)
REMOTE=$(git rev-parse "origin/$BRANCH")

if [ "$LOCAL" = "$REMOTE" ]; then
  echo "$(date -Is) already up to date ($LOCAL)"
  exit 0
fi

echo "$(date -Is) updating $LOCAL -> $REMOTE"
git reset --hard "origin/$BRANCH"

./venv/bin/pip install -q -r requirements.txt
# Confidential/PII SLM (local_ai/slm): only on servers configured with a model folder.
# CPU-only torch wheels; already-satisfied packages make this a no-op.
if systemctl show "$SERVICE" -p Environment | grep -q LOCAL_SLM_MODEL_DIR; then
  ./venv/bin/pip install -q --extra-index-url https://download.pytorch.org/whl/cpu \
    -r local_ai/requirements-slm.txt
fi

sudo systemctl restart "$SERVICE"
sleep 2
systemctl is-active "$SERVICE"
echo "$(date -Is) deployed $REMOTE"
