# Continuous Delivery (CD)

CI (`.github/workflows/securecode-scan.yml`) covers tests, rule scan, and frontend build.  
CD (`.github/workflows/cd.yml`) covers **build → GHCR → VPS (Docker Compose) → smoke → rollback**.

## Flow

```text
push main / workflow_dispatch(deploy)
        │
        ▼
  build & push images → ghcr.io/<owner>/securecode-copilot-{backend,frontend}:sha-XXXXXXX
        │
        ▼
  SSH to VPS → docker compose -f docker-compose.prod.yml pull && up -d
        │
        ▼
  smoke: GET /api/v1/health (+ optional public SMOKE_BASE_URL)
```

Rollback (`workflow_dispatch` → action=`rollback`) restores the previous image pins from `releases/<tag>.env` on the VPS.

## One-time VPS setup

1. Install Docker Engine + Compose plugin.
2. Create deploy directory (default `~/securecode-copilot`).
3. Add the GitHub Actions SSH public key to `~/.ssh/authorized_keys` for `DEPLOY_USER`.
4. Ensure the user can run `docker` / `docker compose` (docker group or root).
5. Optional: copy `deploy/.env.example` → `.env` and set `JWT_SECRET` / `CORS_ORIGINS` / `APP_URL` (CI also writes image pins each deploy).

## GitHub Environments & secrets

Create environments **`staging`** and **`production`** (Settings → Environments).  
Attach protection rules on `production` (required reviewers) if needed.

| Secret | Required | Description |
|--------|----------|-------------|
| `DEPLOY_HOST` | yes (for remote deploy) | VPS hostname or IP |
| `DEPLOY_USER` | yes | SSH user |
| `DEPLOY_SSH_KEY` | yes | Private key (PEM) |
| `DEPLOY_PATH` | no | Remote app dir (default `~/securecode-copilot`) |
| `SMOKE_BASE_URL` | no | Public URL for smoke (e.g. `https://app.example.com`). If empty, smoke runs on the VPS via localhost. |
| `JWT_SECRET` | recommended | App JWT secret |
| `CORS_ORIGINS` | recommended | Comma-separated origins |
| `APP_URL` | recommended | Canonical app URL |
| `LLM_PROVIDER` | no | Default `heuristic` |
| `HTTP_PORT` | no | Host port mapped to frontend (default `80`) |

Without `DEPLOY_*`, CD still **builds and pushes** to GHCR; remote deploy is skipped.

## Trigger

| Event | Behavior |
|-------|----------|
| Push to `main` / `master` | Build/push + deploy **staging** (if secrets set) |
| Actions → CD → **deploy** | Build/push + deploy chosen environment |
| Actions → CD → **rollback** | Redeploy previous tag on that environment (no rebuild) |

## Local / manual deploy

```bash
export BACKEND_IMAGE=ghcr.io/<owner>/securecode-copilot-backend:sha-abc1234
export FRONTEND_IMAGE=ghcr.io/<owner>/securecode-copilot-frontend:sha-abc1234
export RELEASE_TAG=sha-abc1234
export JWT_SECRET=...
docker login ghcr.io
bash deploy/deploy.sh up
bash deploy/deploy.sh smoke
# bash deploy/deploy.sh rollback
# bash deploy/deploy.sh status
```

Compose file: `docker-compose.prod.yml` (image-only, volume for SQLite under `/app/data`).

## GHCR visibility

Packages may be private by default. The deploy step logs in with `GITHUB_TOKEN` on the runner and passes the token over SSH for `docker pull`. For a shared VPS, prefer a fine-grained PAT (`read:packages`) stored as a secret instead of embedding the job token long-term.

## What this is not

- No Kubernetes / Helm (Compose on VPS only).
- No blue/green traffic shift (single compose stack; rollback = previous image tag).
- GPU / CodeT5 serving is not part of this CD path (`LLM_PROVIDER=heuristic` by default).
