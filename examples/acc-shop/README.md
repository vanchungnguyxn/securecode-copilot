# AccMarket (demo vulnerable)

Shop bán account game **cố ý có lỗ hổng** — dùng để test SecureCode Copilot.

## Nội dung

| File | Chức năng giả lập | Lỗ hổng cài sẵn |
|------|-------------------|-----------------|
| `app/main.py` | Flask: đăng ký / đăng nhập / shop / admin | SQLi, CMDi, XSS, pickle, eval, path traversal, hardcode secret |
| `app/payment.py` | Payment / sync | Hardcode API key, path traversal, `os.system` |
| `app/checkout.js` | Express checkout | SQLi-style query, `exec` CMDi, DOM XSS, hardcode key |

## Quét thử

```powershell
# Rule-only (CI action)
.\.venv\Scripts\python.exe action\scan.py examples\acc-shop

# Hybrid (rules + ML context)
.\.venv\Scripts\python.exe examples\acc-shop\run_hybrid_scan.py
```

Hoặc trên UI: upload ZIP thư mục `examples/acc-shop` → Scan repo.

**Không deploy** — chỉ phục vụ demo / luận văn.
