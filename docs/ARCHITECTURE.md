# Tài liệu thiết kế — SecureCode Copilot

## 1. Đặt vấn đề

Phát hiện lỗ hổng bảo mật trong source code thường phân mảnh giữa:
- công cụ SAST rule-based (ít false-negative trên pattern quen, nhưng giải thích/sửa hạn chế)
- LLM general-purpose (giải thích tốt, nhưng không ổn định / thiếu tích hợp CI)

**SecureCode Copilot** kết hợp rule engine đa ngôn ngữ với pipeline LLM (heuristic demo / OpenAI / LoRA fine-tune) để:

1. **Detect** — ánh xạ CWE + OWASP + severity  
2. **Explain** — tại sao lỗi, impact, kịch bản tấn công  
3. **Fix** — đề xuất patch + áp dụng vào editor  
4. **CI/CD** — fail pipeline khi có critical/high  

## 2. Phạm vi ngôn ngữ

Python · JavaScript/TypeScript · Java · C/C++

Bao phủ các lớp lỗ hổng: SQL Injection, Command Injection, XSS, Path Traversal, Deserialization, XXE, Buffer Overflow, Format String, Hardcoded Secrets, SSRF, Prototype Pollution, Eval/RCE.

## 3. Kiến trúc hệ thống

```
Client (React) ──REST──▶ FastAPI
                           ├─ RuleScanner (regex/AST-lite patterns)
                           ├─ LLM Provider (heuristic | openai | local LoRA)
                           └─ Apply-fix / Batch / Rules catalog

CI Job ──▶ action/scan.py ──▶ SARIF + exit code
ML     ──▶ SFT JSONL ──▶ LoRA train ──▶ checkpoints ──▶ LocalLLM
```

## 4. Pipeline dữ liệu & fine-tune

- Dataset mẫu: `ml/datasets/sample/securecode_sft.jsonl` (có thể mở rộng từ Big-Vul, CVEFixes, SecurityEval, OWASP Benchmark).
- Mỗi mẫu sinh 3 task SFT: detect / explain / fix.
- Training: `ml/training/train_lora.py` (PEFT LoRA).
- Eval offline rule engine: `ml/eval/evaluate.py`.

## 5. API

| Method | Path | Mô tả |
|--------|------|--------|
| GET | `/api/v1/health` | Health + provider |
| POST | `/api/v1/scan` | Scan (+ explain + fix) |
| POST | `/api/v1/scan/batch` | Nhiều file |
| POST | `/api/v1/explain` | Giải thích 1 finding |
| POST | `/api/v1/fix` | Sinh patch |
| POST | `/api/v1/apply-fix` | Thay đoạn code |
| GET | `/api/v1/rules` | Catalog rule |

## 6. Đóng góp luận văn / demo

1. Chạy UI, scan 4 sample ngôn ngữ, chụp màn hình findings + explanation + diff.  
2. Chạy `pytest` + `evaluate.py` ghi bảng Precision/Recall.  
3. Chạy GitHub Action / `action/scan.py` trên `examples/vulnerable`.  
4. (Tuỳ chọn GPU) Fine-tune LoRA, so sánh heuristic vs model.  

## 7. Hạn chế & hướng mở rộng

- Rule regex không thay AST/dataflow đầy đủ → tích hợp Semgrep/CodeQL.  
- Dataset mẫu nhỏ → thu thập/gán nhãn từ CVE.  
- Local LLM cần GPU; mặc định heuristic đủ demo.  
- Thêm agent sửa cả file / tạo PR tự động.
