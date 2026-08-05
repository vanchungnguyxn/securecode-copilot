# Hướng dẫn bảo vệ / demo SecureCode Copilot

## Checklist khớp đề tài

| Yêu cầu đề tài | Trạng thái | Chứng minh nhanh |
|----------------|------------|------------------|
| Fine-tune LM local | DONE | `ml/training/train_*.py` + `ml/inference/checkpoints/` |
| Phát hiện | DONE | Hybrid rule + CodeBERT (API/`LLM_PROVIDER=local`) |
| Giải thích | DONE | CodeT5 + heuristic fallback |
| Đề xuất sửa | DONE | CodeT5 fix ~66.7% soft-match + Apply fix UI |
| Đa ngôn ngữ | DONE | Py/JS/TS/Java/C/C++/C#/PHP |
| CI/CD | DONE | `action/scan.py --mode rule\|hybrid` + SARIF + GitHub workflow |
| Đánh giá | DONE | `ml/eval/reports/bench_compare.*` + `figures/` |

## Checklist chạy demo (5–7 phút)

1. **Khởi động** (`backend/.env`: `LLM_PROVIDER=local`, `USE_ML_DETECTOR=true`)
   ```powershell
   # Terminal 1 — API
   cd backend
   ..\.venv\Scripts\uvicorn.exe app.main:app --reload --port 8000

   # Terminal 2 — UI
   cd frontend
   npm run dev
   ```
2. Mở http://127.0.0.1:5173  
3. Sample Py/JS/Java/C → **Scan + Explain + Fix** → **Apply fix**  
4. Upload ZIP `examples/acc-shop` hoặc GitHub URL (repo scan)  
5. CI hybrid local (cùng entrypoint Action):
   ```powershell
   .\scripts\ci_hybrid_scan.ps1
   ```

## CI modes

| Mode | Khi nào | Lệnh |
|------|---------|------|
| **rule** (mặc định GHA) | Nhanh, không cần checkpoint | `python action/scan.py PATH --mode rule` |
| **hybrid** | Có `ml/inference/checkpoints/detector-codebert` | `python action/scan.py PATH --mode hybrid` |

GitHub: job rule luôn chạy; job hybrid qua **workflow_dispatch** chọn `scan_mode=hybrid` (cần checkpoint trên runner/self-hosted).

## Số liệu / ảnh báo cáo

- Metrics: `ml/eval/reports/bench_compare.md` (Hybrid **product** thấp FPR; legacy high-recall để so trade-off)
- Baseline Bandit: `ml/eval/reports/baseline_compare.md` + `figures/10_baseline_vs_bandit.png`
- Figures: `ml/eval/reports/figures/` (`01`…`10`)
- Product defaults: `USE_ML_DISCOVERY=false`, anti_fp thr ≈0.85, `safe_cutoff=0.45`

Tạo lại:
```powershell
.\.venv-ml\Scripts\python.exe ml\eval\bench_compare.py
.\.venv-ml\Scripts\python.exe ml\eval\bench_baselines.py
.\.venv-ml\Scripts\python.exe ml\eval\make_report_figures.py
```

## Slide gợi ý

1. Bài toán Detect–Explain–Fix + CI  
2. Kiến trúc hybrid + fine-tune local  
3. Demo UI live  
4. Bảng Rule vs ML vs Hybrid + ảnh `01`/`04`/`07`  
5. CI rule/hybrid + SARIF  
6. Hạn chế (FPR Devign, fix soft-match, CI cloud cần checkpoint)  

Chi tiết: [ARCHITECTURE.md](ARCHITECTURE.md) · [FINETUNE.md](../ml/FINETUNE.md)
