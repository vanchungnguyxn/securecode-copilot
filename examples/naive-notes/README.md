# MyNotes — web ghi chú cơ bản (không thiết kế bảo mật)

Web Flask giản đơn kiểu đồ án sinh viên: đăng ký, đăng nhập, CRUD ghi chú.

**Không cố ý cài SQLi / CMDi / XSS.** SQL dùng parameterized `?`. Template Jinja auto-escape.

Yếu theo kiểu “chưa nghĩ tới bảo mật” / vibe-code:
- Mật khẩu lưu **plaintext** trong SQLite (không hash)
- `app.secret_key` viết thẳng trong source
- `DEBUG=True`, bind `0.0.0.0`

## Quét thử

Sau khi bổ sung rule vibe-code + train thêm (SecurityEval + vibe patterns):

```powershell
.\.venv\Scripts\python.exe action\scan.py examples\naive-notes
```

Chạy web: `python app/main.py` → http://127.0.0.1:5055  
(Không dùng cổng 5060 — Chrome chặn `ERR_UNSAFE_PORT`.)

Kỳ vọng quét: **hardcoded secret_key**, **plaintext password**, **debug mode**.
