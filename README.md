# SecureCode Copilot

### Fine-tuning mô hình ngôn ngữ cho phát hiện, giải thích và đề xuất sửa lỗ hổng bảo mật trên mã nguồn đa ngôn ngữ, tích hợp CI/CD

<p align="center">
  <img src="ml/eval/reports/figures/09_system_pipeline.png" alt="Pipeline SecureCode Copilot" width="920"/>
</p>

<p align="center">
  <em>Hình 1. Luồng xử lý end-to-end: Rule SAST → CodeBERT (lọc FP) → Hybrid → CodeT5 (explain/fix) → CI/SARIF.</em>
</p>

---

## Tóm tắt

**SecureCode Copilot** là hệ thống hỗ trợ kỹ sư phần mềm viết mã an toàn hơn bằng cách kết hợp:

1. **Phân tích tĩnh dựa trên rule** (map CWE / OWASP, đa ngôn ngữ, giải thích được),
2. **Bộ phân loại CodeBERT fine-tune** để ước lượng xác suất lỗ hổng và **giảm báo sai (false positive)**,
3. **CodeT5-LoRA** để sinh giải thích ngữ cảnh và gợi ý sửa,
4. **Tích hợp CI** qua GitHub Action, xuất **SARIF**.

Hệ thống phục vụ mục tiêu đồ án tốt nghiệp: chứng minh pipeline *detect → explain → fix → gate CI* chạy được trên phần cứng phổ thông (RTX 3050 4GB).

| Khía cạnh | Giá trị |
|-----------|---------|
| Ngôn ngữ | Python, JavaScript/TypeScript, Java, C/C++, C#, PHP |
| Chế độ detect | Rule-only · Hybrid (product) · ML discovery (tuỳ chọn) |
| LLM | `heuristic` · `local` (CodeT5-LoRA) · `openai` |
| CI | GitHub Actions + `action/scan.py` → SARIF |

---

## 1. Đặt vấn đề

Công cụ SAST rule-based bắt tốt các mẫu quen thuộc nhưng hạn chế về giải thích và đề xuất vá. LLM mục đích chung viết mô tả hay nhưng thiếu ổn định, dễ ảo giác, và khó gắn vào gate CI.

SecureCode Copilot tách rõ vai trò:

- **Rule** — bắt pattern đã biết (recall cao trên class phổ biến),
- **CodeBERT** — chấm điểm ngữ cảnh để *giữ / bỏ* finding (ưu tiên giảm FP),
- **CodeT5** — diễn giải và gợi ý patch; khi sinh kém thì fallback template có kiểm soát.

---

## 2. Kiến trúc hệ thống

```
React UI  ──REST──▶  FastAPI
                       ├─ RuleScanner (CWE / OWASP)
                       ├─ CodeBERT hybrid filter
                       ├─ LocalLLM / Heuristic / OpenAI
                       └─ Apply-fix · Batch · Repo ZIP/GitHub

GitHub Actions ──▶ action/scan.py ──▶ JSON + SARIF artifact
ML pipeline    ──▶ dataset → train CodeBERT / CodeT5-LoRA → checkpoints
```

Chi tiết thiết kế: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) · Demo: [`docs/DEMO.md`](docs/DEMO.md).

---

## 3. Dữ liệu huấn luyện

Detector được huấn luyện trên hỗn hợp **CodeXGLUE Defect Detection (Devign)**, mẫu curated / vibe-coding, **hard-negatives**, SecurityEval và cặp CVEFixes. Nhánh SFT (explain/fix) mở rộng bằng patch đa ngôn ngữ từ CVEFixes.

<p align="center">
  <img src="ml/eval/reports/figures/05_dataset_composition.png" alt="Thành phần dữ liệu huấn luyện" width="920"/>
</p>

<p align="center">
  <em>Hình 2. Thành phần dữ liệu: nguồn detector (Σ ≈ 5 329), cân bằng nhãn, phân bố ngôn ngữ SFT.</em>
</p>

<p align="center">
  <img src="ml/eval/reports/figures/06_sft_task_mix.png" alt="Phân bố task SFT" width="720"/>
</p>

<p align="center">
  <em>Hình 3. Phân bố nhiệm vụ SFT (detect / explain / fix) và nguồn curated vs CVEFixes.</em>
</p>

---

## 4. Kết quả thực nghiệm

### 4.1. Detector CodeBERT — chiến lược ngưỡng

Trên GPU **RTX 3050 4GB**, train ≈ **6 322** mẫu (oversample). Product ưu tiên chiến lược **Anti-FP** (precision cao, FPR thấp) thay vì Maximized F1 với FPR không chấp nhận được trên sản phẩm.

<p align="center">
  <img src="ml/eval/reports/figures/08_codebert_threshold_strategies.png" alt="Ngưỡng CodeBERT" width="900"/>
</p>

<p align="center">
  <em>Hình 4. Anti-FP · Hybrid · Balanced — trade-off precision / recall / FPR.</em>
</p>

### 4.2. Rule · Hybrid · ML trên bộ đa ngôn ngữ

<p align="center">
  <img src="ml/eval/reports/figures/01_hybrid_vs_rule_ml_multilingual.png" alt="Hybrid vs Rule vs ML" width="900"/>
</p>

<p align="center">
  <em>Hình 5. Precision / Recall / F1 trên tập đa ngôn ngữ + hard-negative.</em>
</p>

<p align="center">
  <img src="ml/eval/reports/figures/03_hybrid_confusion_multilingual.png" alt="Confusion matrix Hybrid" width="520"/>
</p>

<p align="center">
  <em>Hình 6. Ma trận nhầm lẫn chế độ Hybrid (product).</em>
</p>

### 4.3. Đối chiếu trên mã C (Devign mix) và baseline

<p align="center">
  <img src="ml/eval/reports/figures/02_detector_devign_mix.png" alt="Devign mix" width="900"/>
</p>

<p align="center">
  <em>Hình 7. So sánh Rule / ML / Hybrid trên detector test kiểu Devign.</em>
</p>

<p align="center">
  <img src="ml/eval/reports/figures/10_baseline_vs_bandit.png" alt="Baseline Bandit Semgrep" width="900"/>
</p>

<p align="center">
  <em>Hình 8. So với Bandit và Semgrep trên bộ cặp Python có nhãn (xem số liệu trong report).</em>
</p>

Bảng tóm tắt baseline (Python labeled pairs):

| Phương pháp | Precision | Recall | F1 | FPR |
|-------------|-----------|--------|----|-----|
| SCC Rule-only | 0.827 | 0.917 | 0.870 | 0.192 |
| SCC Hybrid | 0.821 | 0.917 | 0.866 | 0.200 |
| Bandit | 0.628 | 0.758 | 0.687 | 0.450 |
| Semgrep | 0.938 | 0.125 | 0.221 | 0.008 |

Chi tiết: [`ml/eval/reports/baseline_compare.md`](ml/eval/reports/baseline_compare.md) · [`ml/eval/reports/bench_compare.md`](ml/eval/reports/bench_compare.md).

### 4.4. CodeT5 — chất lượng gợi ý sửa (soft-match)

Soft-match tăng từ giai đoạn mixed SFT ban đầu lên **≈ 63.3%** sau khi bổ sung patch CVEFixes thật (eval *n* = 60).

<p align="center">
  <img src="ml/eval/reports/figures/04_codet5_fix_softmatch.png" alt="CodeT5 soft-match" width="720"/>
</p>

<p align="center">
  <em>Hình 9. Tiến triển soft-match của module fix CodeT5-LoRA.</em>
</p>

### 4.5. Bằng chứng quét repo demo

<p align="center">
  <img src="ml/eval/reports/figures/07_demo_repo_scan_counts.png" alt="Demo repo scan" width="900"/>
</p>

<p align="center">
  <em>Hình 10. Số finding theo severity trên các repo trong `examples/` (RuleScanner).</em>
</p>

---

## 5. Chạy nhanh

### Yêu cầu

- Python 3.11+ · Node.js 20+  
- (Tuỳ chọn) CUDA cho inference CodeBERT / CodeT5  
- Docker (tuỳ chọn)

### Backend

```bash
cd backend
python -m venv .venv
# Windows: .venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env   # chỉnh LLM_PROVIDER nếu cần
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

API docs: http://127.0.0.1:8000/docs

> Recommendation trên máy đã fine-tune: đặt `LLM_PROVIDER=local` và chạy backend bằng **`.venv-ml`** (có `torch` / `peft`) để CodeT5 thực sự được nạp.

### Frontend

```bash
cd frontend
npm install
npm run dev
```

UI: http://127.0.0.1:5173

### Docker Compose

```bash
docker compose up --build
```

### Fine-tune (local)

Xem [`ml/FINETUNE.md`](ml/FINETUNE.md):

```powershell
powershell -ExecutionPolicy Bypass -File scripts\train_local.ps1
```

Tái tạo biểu đồ luận văn:

```powershell
.\.venv-ml\Scripts\python.exe ml\eval\make_report_figures.py
```

---

## 6. CI / GitHub Actions

Workflow: [`.github/workflows/securecode-scan.yml`](.github/workflows/securecode-scan.yml)

| Job | Việc làm |
|-----|----------|
| `backend-tests` | `pytest` |
| `security-scan-rule` | Quét `examples/*` bằng rule, xuất SARIF |
| `frontend-build` | `npm run build` |
| `security-scan-hybrid` | Chỉ khi chạy tay (`workflow_dispatch`, mode `hybrid`) |

Composite action: [`action/`](action/). Repo demo: [vanchungnguyxn/securecode-copilot](https://github.com/vanchungnguyxn/securecode-copilot).

> **Lưu ý:** job Actions cần tài khoản GitHub không bị khoá billing. Có thể chạy tương đương local bằng `action/scan.py` (đã kiểm chứng trên máy phát triển).

---

## 7. Cấu trúc thư mục

```
securecode-copilot/
├── backend/                 # FastAPI: scan · explain · fix · repo
├── frontend/                # React + Vite workspace
├── ml/
│   ├── datasets/            # Chuẩn bị dữ liệu + mẫu SFT
│   ├── training/            # train_detector · train_codet5_lora
│   ├── eval/reports/        # Số liệu + figures luận văn
│   └── inference/checkpoints/  # (không commit) model local
├── action/                  # GitHub Action composite
├── examples/                # Repo demo có lỗ hổng / gần an toàn
├── docs/                    # Kiến trúc · kịch bản demo
└── scripts/                 # train_local · demo_scan
```

### Biến môi trường (`backend/.env`)

| Biến | Ý nghĩa |
|------|---------|
| `LLM_PROVIDER` | `heuristic` \| `local` \| `openai` |
| `USE_ML_DETECTOR` | Bật lọc FP bằng CodeBERT |
| `USE_ML_DISCOVERY` | Bật discovery thuần ML (mặc định tắt) |
| `OPENAI_API_KEY` | Chỉ khi `openai` |
| `CORS_ORIGINS` | Origin frontend |

---

## 8. Hạn chế và hướng mở rộng

- CodeT5 trên 4GB VRAM dễ sinh lặp; hệ thống có gate chống degenerate và fallback heuristic theo rule (đặc biệt HARDCODE).  
- Anti-FP làm giảm recall discovery; vì vậy product dựa **rule + hybrid filter**, không dựa ML-only.  
- Hướng mở: dataset hard-negative theo từng CWE, retrain định kỳ, upload SARIF vào GitHub Code Scanning, bổ sung CD nếu cần.

---

## Giấy phép

MIT — phục vụ mục đích học thuật / đồ án tốt nghiệp.

<p align="center">
  <sub>Figures được sinh bằng <code>ml/eval/make_report_figures.py</code> · cập nhật theo checkpoint và meta dữ liệu gần nhất.</sub>
</p>
