# Figures for thesis / report

Mỗi ảnh trả lời **một câu hỏi** — layout đã chỉnh để tránh đè chữ.

| File | Câu hỏi / nội dung |
|------|---------------------|
| `01_hybrid_vs_rule_ml_multilingual.png` | SCC Rule / Hybrid / ML phát hiện lỗ hổng ra sao? |
| `02_detector_devign_mix.png` | Trên mã C thật (Devign) thì sao? |
| `03_hybrid_confusion_multilingual.png` | Hybrid đúng / sai ở đâu? |
| `04_codet5_fix_softmatch.png` | Gợi ý sửa mã tiến bộ thế nào (+CVEFixes)? |
| `05_dataset_composition.png` | Train bằng dữ liệu gì? |
| `06_sft_task_mix.png` | CodeT5 học fix / explain / từ đâu? |
| `07_demo_repo_scan_counts.png` | Quét repo demo thấy gì? |
| `08_codebert_threshold_strategies.png` | Vì sao chọn Anti-FP threshold? |
| `09_system_pipeline.png` | Pipeline hệ thống end-to-end |
| `10_baseline_vs_bandit.png` | So với Bandit & Semgrep |

```powershell
.\.venv-ml\Scripts\python.exe ml\eval\make_report_figures.py
```
