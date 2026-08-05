# Train SecureCode Copilot on this machine (RTX 3050 4GB + 60GB RAM)
# Usage: powershell -ExecutionPolicy Bypass -File scripts\train_local.ps1

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

Write-Host "==> Ensuring Python 3.12 venv at repo root (.venv-ml)" -ForegroundColor Cyan
$py = Join-Path $Root ".venv-ml\Scripts\python.exe"

# Repair broken venv (pip launcher pointing at backend\.venv-ml)
$broken = $false
if (Test-Path $py) {
  try {
    & $py -c "import sys; print(sys.prefix)" | Out-Null
  } catch {
    $broken = $true
  }
} else {
  $broken = $true
}

# Detect shebang pointing to missing backend\.venv-ml
$pipPath = Join-Path $Root ".venv-ml\Scripts\pip.exe"
if ((Test-Path $pipPath) -and -not (Test-Path (Join-Path $Root "backend\.venv-ml\Scripts\python.exe"))) {
  $probe = & cmd /c "`"$pipPath`" --version" 2>&1 | Out-String
  if ($probe -match "Unable to create process|cannot find the file") {
    $broken = $true
  }
}

if ($broken -or -not (Test-Path $py)) {
  Write-Host "Recreating .venv-ml (previous venv was broken/mislinked)..." -ForegroundColor Yellow
  if (Test-Path (Join-Path $Root ".venv-ml")) {
    Remove-Item -Recurse -Force (Join-Path $Root ".venv-ml")
  }
  if (Test-Path (Join-Path $Root "backend\.venv-ml")) {
    Remove-Item -Recurse -Force (Join-Path $Root "backend\.venv-ml")
  }
  py -3.12 -m venv (Join-Path $Root ".venv-ml")
  $py = Join-Path $Root ".venv-ml\Scripts\python.exe"
}

Write-Host "==> Installing PyTorch CUDA + ML deps via python -m pip" -ForegroundColor Cyan
& $py -m pip install --upgrade pip
& $py -m pip install torch torchvision --index-url https://download.pytorch.org/whl/cu124
& $py -m pip install -r (Join-Path $Root "ml\requirements-ml.txt")

Write-Host "==> Preparing datasets (Devign + curated + hard negatives)" -ForegroundColor Cyan
& $py (Join-Path $Root "ml\datasets\prepare_datasets.py") --out (Join-Path $Root "ml\datasets\processed") --max-devign 4000

Write-Host "==> Fine-tuning CodeBERT detector (anti-FP)" -ForegroundColor Cyan
& $py (Join-Path $Root "ml\training\train_detector.py") `
  --data (Join-Path $Root "ml\datasets\processed\detector") `
  --epochs 5 --batch-size 8 `
  --min-precision 0.75 `
  --output (Join-Path $Root "ml\inference\checkpoints\detector-codebert")

Write-Host "==> Fine-tuning CodeT5-base LoRA (explain + fix)" -ForegroundColor Cyan
& $py (Join-Path $Root "ml\training\train_codet5_lora.py") `
  --data (Join-Path $Root "ml\datasets\processed\sft.jsonl") `
  --epochs 5 --batch-size 1 --grad-accum 8 `
  --output (Join-Path $Root "ml\inference\checkpoints\codet5-lora")

Write-Host "==> Evaluating detector FP" -ForegroundColor Cyan
& $py (Join-Path $Root "ml\eval\eval_detector.py") --ckpt (Join-Path $Root "ml\inference\checkpoints\detector-codebert")

Write-Host "==> Done. Set LLM_PROVIDER=local in backend/.env" -ForegroundColor Green
Write-Host "Note: hybrid scan uses 'hybrid_threshold' (recall-friendly). Strict anti-FP uses 'threshold'." -ForegroundColor DarkGray
