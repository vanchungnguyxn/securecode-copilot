# Vibe-auth demo — INTENTIONAL insecure auth (Firebase + JWT)

Mô phỏng app do vibe-code: đăng ký/đăng nhập JWT lỏng + Firestore rules mở + lộ key.

```powershell
.\.venv\Scripts\python.exe action\scan.py examples\vibe-auth
```

Kỳ vọng bắt được: Firebase `allow ... if true`, JWT hardcode / decode không verify, thiếu auth middleware, CORS `*`, hardcode secret, debug.
