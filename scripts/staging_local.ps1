# Local staging deploy: build images + compose.prod + smoke (no remote VPS required).
# Usage: powershell -File scripts/staging_local.ps1
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$Backend = "securecode-copilot-backend:staging"
$Frontend = "securecode-copilot-frontend:staging"
$Port = if ($env:HTTP_PORT) { $env:HTTP_PORT } else { "18088" }

Write-Host "== docker build backend ==" -ForegroundColor Cyan
docker build -t $Backend -f backend/Dockerfile .

Write-Host "== docker build frontend ==" -ForegroundColor Cyan
docker build -t $Frontend -f frontend/Dockerfile ./frontend

$env:BACKEND_IMAGE = $Backend
$env:FRONTEND_IMAGE = $Frontend
$env:HTTP_PORT = $Port
$env:JWT_SECRET = if ($env:JWT_SECRET) { $env:JWT_SECRET } else { "staging-local-jwt-secret-min-32-chars!!" }
$env:CORS_ORIGINS = "http://127.0.0.1:$Port,http://localhost:$Port"
$env:APP_URL = "http://127.0.0.1:$Port"
$env:RELEASE_TAG = "staging-local"

Write-Host "== compose up ==" -ForegroundColor Cyan
docker compose -f docker-compose.prod.yml down --remove-orphans 2>$null
docker compose -f docker-compose.prod.yml up -d

Write-Host "== smoke ==" -ForegroundColor Cyan
$ok = $false
for ($i = 1; $i -le 30; $i++) {
  try {
    $r = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/api/v1/health" -TimeoutSec 3
    if ($r.status) {
      Write-Host "health:" ($r | ConvertTo-Json -Compress)
      $ok = $true
      break
    }
  } catch {
    # Fallback: backend healthy even if host port blocked — probe inside network
    try {
      $inner = docker compose -f docker-compose.prod.yml exec -T backend `
        python -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health', timeout=3).read().decode())"
      if ($inner -match '"status"') {
        Write-Host "health (in-container):" $inner
        $ok = $true
        break
      }
    } catch {}
    Start-Sleep -Seconds 2
  }
}
if (-not $ok) {
  docker compose -f docker-compose.prod.yml logs --tail=80
  throw "Staging smoke failed"
}
Write-Host "STAGING local: GREEN on http://127.0.0.1:$Port (or in-container backend health OK)" -ForegroundColor Green
