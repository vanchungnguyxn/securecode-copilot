# SecureCode Copilot

**Fine-tuning mô hình ngôn ngữ để phát hiện, giải thích và đề xuất tự động sửa lỗ hổng bảo mật trong source code đa ngôn ngữ, tích hợp CI/CD**

SecureCode Copilot là hệ thống hỗ trợ phát triển an toàn: quét lỗ hổng bảo mật (SAST + LLM), giải thích rủi ro theo ngữ cảnh, và đề xuất/áp dụng bản vá tự động — hỗ trợ **Python, JavaScript/TypeScript, Java, C/C++**, kèm **GitHub Action** cho CI/CD.

## Tính năng chính

| Module | Mô tả |
|--------|--------|
| **Detect** | Quét đa ngôn ngữ bằng rule engine + mô hình phân loại lỗ hổng |
| **Explain** | Giải thích CWE/OWASP, impact, attack scenario bằng LLM |
| **Fix** | Đề xuất patch diff và code đã sửa; áp dụng 1-click trên UI |
| **CI/CD** | GitHub Action fail PR khi tìm thấy severity cao |
| **ML Pipeline** | Dataset, fine-tune (LoRA), eval, serve inference |

## Kiến trúc

```
┌─────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  Web UI     │────▶│  FastAPI Backend │────▶│  Rule Scanner   │
│  (React)    │     │  /scan /explain  │     │  + LLM Engine   │
└─────────────┘     │  /fix /health    │     └─────────────────┘
                    └────────┬─────────┘
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
        ┌──────────┐  ┌────────────┐  ┌─────────────┐
        │ HF/Local │  │  OpenAI    │  │ GitHub Act. │
        │ LoRA model│  │  (optional)│  │  CI scan    │
        └──────────┘  └────────────┘  └─────────────┘
```

## Quick start

### Yêu cầu
- Python 3.11+
- Node.js 20+
- Docker (tuỳ chọn)

### 1. Backend

```bash
cd backend
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/macOS:
# source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

API docs: http://localhost:8000/docs

### 2. Frontend

```bash
cd frontend
npm install
npm run dev
```

UI: http://localhost:5173

### 3. Docker Compose (full stack)

```bash
docker compose up --build
```

- UI: http://localhost:5173  
- API: http://localhost:8000

### 4. GitHub Action

Xem [`.github/workflows/securecode-scan.yml`](.github/workflows/securecode-scan.yml) và action tại [`action/`](action/).

## API nhanh

```bash
curl -X POST http://localhost:8000/api/v1/scan \
  -H "Content-Type: application/json" \
  -d "{\"code\": \"query = \\\"SELECT * FROM users WHERE id = \\\" + user_id\", \"language\": \"python\", \"filename\": \"app.py\"}"
```

## Thư mục dự án

```
securecode-copilot/
├── backend/           # FastAPI: scan, explain, fix
├── frontend/          # React + Vite UI
├── ml/                # Dataset, fine-tune LoRA, eval
├── action/            # GitHub Action composite
├── examples/          # Mẫu code vulnerable theo ngôn ngữ
├── docs/              # Tài liệu luận văn / thiết kế
├── scripts/           # Tiện ích demo
└── docker-compose.yml
```

## Biến môi trường

Sao chép `backend/.env.example` → `backend/.env`:

| Biến | Ý nghĩa |
|------|---------|
| `LLM_PROVIDER` | `heuristic` \| `openai` \| `local` |
| `OPENAI_API_KEY` | Nếu dùng OpenAI |
| `MODEL_PATH` | Đường dẫn LoRA/local model |
| `CORS_ORIGINS` | Origin frontend |

Mặc định chạy **heuristic + rule engine** (không cần GPU/API key) — đủ demo bảo vệ.

## Fine-tune thật (không gọi API)

Máy profile sẵn (RTX 3050 4GB + 60GB RAM): dùng **CodeBERT** (detector chống FP) + **CodeT5-base LoRA** (explain/fix).

Chi tiết: [`ml/FINETUNE.md`](ml/FINETUNE.md)

```powershell
powershell -ExecutionPolicy Bypass -File scripts\train_local.ps1
```

Sau train: đặt `LLM_PROVIDER=local` trong `backend/.env`.

## Giấy phép

MIT — dùng cho mục đích học thuật / tốt nghiệp.
