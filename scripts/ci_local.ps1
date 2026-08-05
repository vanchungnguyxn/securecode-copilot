# Mirror GitHub Actions SecureCode Copilot CI on a local machine.
# Usage: powershell -File scripts/ci_local.ps1
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

Write-Host "== backend-tests ==" -ForegroundColor Cyan
Push-Location backend
if (Test-Path ..\.venv\Scripts\python.exe) {
  ..\.venv\Scripts\python.exe -m pip install -q -r requirements.txt
  ..\.venv\Scripts\python.exe -m pytest -q
} else {
  python -m pip install -q -r requirements.txt
  python -m pytest -q
}
Pop-Location

Write-Host "== security-scan-rule ==" -ForegroundColor Cyan
$py = if (Test-Path .\.venv\Scripts\python.exe) { ".\.venv\Scripts\python.exe" } else { "python" }
& $py -m pip install -q -r backend/requirements.txt
& $py action/scan.py examples/acc-shop examples/vibe-auth examples/lang-extra `
  --mode rule --fail-on critical `
  --json-out ci-rule-scan.json --sarif ci-rule-scan.sarif
& $py -c "import json; d=json.load(open('ci-rule-scan.json',encoding='utf-8')); print('findings', len(d)); assert len(d)>0"

Write-Host "== frontend-build ==" -ForegroundColor Cyan
Push-Location frontend
if (Test-Path .\node_modules\vite\bin\vite.js) {
  npm run build
} else {
  npm install
  if ($LASTEXITCODE -ne 0) { throw "npm install failed" }
  npm run build
}
if ($LASTEXITCODE -ne 0) { throw "frontend build failed" }
Pop-Location

Write-Host "CI local: GREEN" -ForegroundColor Green
