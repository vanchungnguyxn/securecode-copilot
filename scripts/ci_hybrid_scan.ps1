# Local CI hybrid smoke (same entrypoint as GitHub Action)
# Requires fine-tuned checkpoint under ml/inference/checkpoints/detector-codebert

$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)

$py = ".\.venv-ml\Scripts\python.exe"
if (-not (Test-Path $py)) { $py = ".\.venv\Scripts\python.exe" }

Write-Host "== Hybrid CI scan (CodeBERT filters rule hits) ==" -ForegroundColor Cyan
& $py action\scan.py examples\acc-shop examples\naive-notes examples\ticket-channel `
  --mode hybrid `
  --fail-on critical `
  --json-out ml\eval\reports\ci_hybrid_local.json `
  --sarif ml\eval\reports\ci_hybrid_local.sarif

# Also install backend deps into ML venv once if needed:
#   .\.venv-ml\Scripts\python.exe -m pip install -r backend\requirements.txt

Write-Host "Wrote ml\eval\reports\ci_hybrid_local.json / .sarif" -ForegroundColor Green
