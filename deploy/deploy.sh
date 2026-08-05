# Deploy helpers for VPS + docker compose prod
#
# Layout on server (DEPLOY_PATH):
#   docker-compose.prod.yml
#   .env                 # BACKEND_IMAGE, FRONTEND_IMAGE, secrets
#   .release_current     # currently running tag
#   .release_previous    # previous tag (rollback)
#   releases/<tag>.env   # snapshot of image pins

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.prod.yml}"

log() { echo "[deploy] $*"; }

require_env() {
  local k
  for k in "$@"; do
    if [ -z "${!k:-}" ]; then
      echo "Missing required env: $k" >&2
      exit 1
    fi
  done
}

cmd_write_env() {
  require_env BACKEND_IMAGE FRONTEND_IMAGE
  local out="${1:-.env}"
  cat >"$out" <<EOF
BACKEND_IMAGE=${BACKEND_IMAGE}
FRONTEND_IMAGE=${FRONTEND_IMAGE}
LLM_PROVIDER=${LLM_PROVIDER:-heuristic}
USE_ML_DETECTOR=${USE_ML_DETECTOR:-false}
USE_ML_DISCOVERY=${USE_ML_DISCOVERY:-false}
CORS_ORIGINS=${CORS_ORIGINS:-http://localhost}
DATABASE_URL=${DATABASE_URL:-sqlite:///./data/scc.db}
JWT_SECRET=${JWT_SECRET:-change-me-in-production-min-32-chars}
BILLING_MOCK=${BILLING_MOCK:-true}
APP_URL=${APP_URL:-http://localhost}
HTTP_PORT=${HTTP_PORT:-80}
EOF
  log "wrote $out"
}

cmd_up() {
  require_env BACKEND_IMAGE FRONTEND_IMAGE
  local tag="${RELEASE_TAG:-unknown}"
  mkdir -p releases
  if [ -f .release_current ]; then
    cp .release_current .release_previous
  fi
  echo "$tag" >.release_current
  cmd_write_env ".env"
  cmd_write_env "releases/${tag}.env"
  docker compose -f "$COMPOSE_FILE" pull
  docker compose -f "$COMPOSE_FILE" up -d --remove-orphans
  log "deployed tag=$tag"
  docker compose -f "$COMPOSE_FILE" ps
}

cmd_rollback() {
  if [ ! -f .release_previous ]; then
    echo "No .release_previous — cannot rollback" >&2
    exit 1
  fi
  local prev
  prev="$(cat .release_previous)"
  if [ ! -f "releases/${prev}.env" ]; then
    echo "Missing releases/${prev}.env" >&2
    exit 1
  fi
  log "rolling back to $prev"
  # swap pointers
  if [ -f .release_current ]; then
    local cur
    cur="$(cat .release_current)"
    echo "$cur" >.release_previous
  fi
  echo "$prev" >.release_current
  # shellcheck disable=SC1090
  set -a
  # load previous pins
  # shellcheck disable=SC1091
  . "releases/${prev}.env"
  set +a
  cmd_write_env ".env"
  docker compose -f "$COMPOSE_FILE" pull
  docker compose -f "$COMPOSE_FILE" up -d --remove-orphans
  log "rollback complete → $prev"
  docker compose -f "$COMPOSE_FILE" ps
}

cmd_smoke() {
  local base="${SMOKE_BASE_URL:-http://127.0.0.1:${HTTP_PORT:-80}}"
  local tries="${SMOKE_TRIES:-20}"
  local i
  log "smoke against $base"
  for i in $(seq 1 "$tries"); do
    if curl -fsS "$base/api/v1/health" | grep -q '"status"'; then
      log "API health OK"
      curl -fsS -o /dev/null -w "frontend HTTP %{http_code}\n" "$base/"
      return 0
    fi
    sleep 3
  done
  echo "Smoke failed after ${tries} tries" >&2
  docker compose -f "$COMPOSE_FILE" logs --tail=80 || true
  exit 1
}

cmd_status() {
  docker compose -f "$COMPOSE_FILE" ps
  echo "current=$(cat .release_current 2>/dev/null || echo none)"
  echo "previous=$(cat .release_previous 2>/dev/null || echo none)"
}

usage() {
  cat <<EOF
Usage: $0 <up|rollback|smoke|status|write-env>
EOF
}

main() {
  local cmd="${1:-}"
  case "$cmd" in
    up) cmd_up ;;
    rollback) cmd_rollback ;;
    smoke) cmd_smoke ;;
    status) cmd_status ;;
    write-env) cmd_write_env "${2:-.env}" ;;
    *) usage; exit 1 ;;
  esac
}

main "$@"
