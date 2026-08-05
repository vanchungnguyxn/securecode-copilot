# SimpleCMS — trang web đơn giản + admin sửa nội dung

Site giới thiệu cá nhân/shop nhỏ: trang chủ công khai, trang admin đăng nhập để sửa tiêu đề/nội dung.
Không cố ý cài SQLi/XSS/CMDi — SQL parameterized, Jinja auto-escape, mật khẩu hash bằng werkzeug.

```powershell
pip install -r requirements.txt
python app.py
# http://127.0.0.1:5070  |  admin: http://127.0.0.1:5070/admin
# user mặc định: admin / admin123 (đổi sau khi chạy)

.\.venv\Scripts\python.exe action\scan.py examples\simple-cms
```
