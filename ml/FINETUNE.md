# Fine-tuning thật — SecureCode Copilot (không gọi API)

> Máy local đã profile: **AMD Ryzen 5 5600H (6C/12T) · RAM 60GB · RTX 3050 Laptop 4GB VRAM**.  
> Toàn bộ detect / explain / fix dùng **model tự fine-tune trên máy**, không phụ thuộc OpenAI.

## 1. Chiến lược 2-model (vừa VRAM, giảm FP)

| Vai trò | Base model | Vì sao chọn | Fit 4GB? |
|---------|------------|-------------|----------|
| **Detector (chống FP)** | [`microsoft/codebert-base`](https://huggingface.co/microsoft/codebert-base) (~125M) | Encoder mạnh cho classification; threshold → tận Precision | Có, thoải mái |
| **Explainer/Fixer** | [`Salesforce/codet5-base`](https://huggingface.co/Salesforce/codet5-base) (~220M) | Seq2seq phù hợp rewrite/patch; train LoRA | Có (fp16 + LoRA) |

**Không chọn 7B/3B full** trên RTX 3050 4GB (OOM). RAM 60GB dùng cho: cache dataset, preprocess song song CPU, gradient checkpointing nếu cần.

Optional nâng cấp sau (Colab 16–24GB): `deepseek-ai/deepseek-coder-1.3b-instruct` hoặc `Qwen2.5-Coder-1.5B` QLoRA — cùng format checkpoint.

## 2. Dataset — đủ lớn để “giỏi” và ít FP

| Nguồn | Task | Ngôn ngữ | Cách lấy |
|-------|------|----------|----------|
| **CodeXGLUE Defect / Devign** | binary vulnerable vs safe | C | `prepare_datasets.py --source devign` |
| **CVEFixes-style pairs** (curated + expand) | detect + explain + fix | Py/JS/Java/C | bundle sẵn + generator |
| **Vibe-code / missing-security** | plaintext pwd, weak hash, secret_key, JWT, CORS, DEBUG, **Firebase open rules**, **missing auth middleware**, IDOR-ish routes | Py/JS/Java | `vibe_patterns.py` + SAST rules + `examples/vibe-auth` |
| **PHP / C# / C++ curated + bulk** | SQLi, CMDi, XSS, deser, LFI, BinaryFormatter… | php, csharp, cpp | `lang_extra.py` |
| **[secure_dataset_cvefixes](https://huggingface.co/datasets/Younis2003/secure_dataset_cvefixes)** | CVE patch pairs (PHP/C++ nhiều; C# ít) | multi | `prepare_datasets.py --max-cvefixes-lang 200` |
| **[DiverseVul](https://github.com/wagner-group/diversevul)** (tuỳ chọn) | C/C++ function-level vuln detect | C/C++ | tải GitHub nếu cần scale |
| **[SecurityEval](https://huggingface.co/datasets/s2e-lab/SecurityEval)** | insecure snippets theo CWE (LLM codegen) | Python | `prepare_datasets.py --max-securityeval 500` |
| **Hard negatives** | chống FP | multi | code “trông nguy hiểm” nhưng an toàn (prepared stmt, `textContent`, `snprintf`…) |
| **(Tuỳ chọn)** Full [CVEFixes](https://github.com/secureIT-project/CVEfixes) DB | patch pairs | multi | `--source cvefixes --cvefixes-db path.db` |

**Công thức giảm FP (trọng tâm luận văn):**

1. Train detector trên **cân bằng** `label=1` (vuln) / `label=0` (safe).  
2. ≥30% negative là **hard negative** (giống pattern nguy hiểm nhưng đã sanitize).  
3. Chọn threshold theo **Precision ≥ target** (mặc định 0.90) trên validation, không chỉ max F1.  
4. Inference hybrid: `final = rule_hit AND ml_score ≥ τ` hoặc `ml_score ≥ τ_high` — bỏ finding rule nếu ML chắc là safe.

## 3. Pipeline lệnh

```bash
# Dùng Python 3.12 cho ML (ổn định với torch)
py -3.12 -m venv .venv-ml
.\.venv-ml\Scripts\activate
pip install -r ml\requirements-ml.txt

# 1) Chuẩn bị dataset
python ml/datasets/prepare_datasets.py --out ml/datasets/processed --max-devign 8000

# 2) Fine-tune detector (CodeBERT)
python ml/training/train_detector.py --data ml/datasets/processed/detector --epochs 3

# 3) Fine-tune explain+fix (CodeT5 + LoRA)
python ml/training/train_codet5_lora.py --data ml/datasets/processed/sft.jsonl --epochs 3

# 4) Đánh giá FP / Precision / Recall
python ml/eval/eval_detector.py --ckpt ml/inference/checkpoints/detector-codebert
python ml/eval/eval_sft.py --ckpt ml/inference/checkpoints/codet5-lora
```

Backend tự load checkpoint local khi `LLM_PROVIDER=local`.

## 4. Artifact sau train

```
ml/inference/checkpoints/
  detector-codebert/     # classification head
  codet5-lora/           # LoRA adapter + tokenizer
  thresholds.json        # τ tối ưu Precision
```

## 6. Kết quả train trên máy này (đã chạy)

Hardware: RTX 3050 Laptop 4GB · CUDA · Python 3.12 (`.venv-ml`)

| Model | Checkpoint | Ghi chú |
|-------|------------|---------|
| CodeBERT detector | `ml/inference/checkpoints/detector-codebert` | Threshold tối ưu Precision≥0.9 |
| CodeT5-base LoRA | `ml/inference/checkpoints/codet5-lora` | explain + fix |

## 7. Dataset explain/fix + benchmark (local)

```powershell
.\.venv-ml\Scripts\python.exe ml\datasets\build_fix_sft.py --n-per-template 14 --fix-repeat 3
.\.venv-ml\Scripts\python.exe ml\training\train_codet5_lora.py --data ml\datasets\processed\sft_fix.jsonl --epochs 4 --tasks fix,explain --lora-r 16
.\.venv-ml\Scripts\python.exe ml\eval\bench_compare.py
# → ml/eval/reports/bench_compare.md
```

CodeT5 **fix soft-match ~0.67** (n=60; trước ~0.05). Product: CodeT5 beam-4 + heuristic fallback nếu output kém.

Bảng detect (multilingual pairs + hardneg): Hybrid ưu tiên Recall sản phẩm.

**Vấn đề:** anti-FP threshold (P≥0.9) → Recall ~8–13% nếu dùng để lọc rule.  
**Fix product:**

1. Retrain CodeBERT với **class weight + oversample vuln** (boost recall).  
2. Threshold **balanced** (max F1) cho **ML discovery** windows → val Recall ~**0.90**.  
3. **safe_cutoff≈0.28**: chỉ suppress rule hit khi ML chắc SAFE (không nuốt lỗ hổng thật).  
4. **Context window ±14 dòng** khi chấm điểm (hiểu quanh hàm, không chỉ 1 dòng).  
5. **Repo scan**: GitHub URL / ZIP — đọc nhiều file trong repo user push.

API:

- `POST /api/v1/scan/repo` `{ "github_url": "https://github.com/owner/repo" }`
- `POST /api/v1/scan/repo/upload` (multipart zip)

UI: ô GitHub URL + Upload ZIP trên trang chính.
