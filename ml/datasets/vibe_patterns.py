"""Vibe-code / missing-security patterns for detector + SFT.

Common AI-generated web pitfalls (Invicti / research):
- plaintext password storage/compare (CWE-256)
- weak password hashing md5/sha (CWE-327)
- hardcoded secret_key / JWT / connection strings (CWE-798)
- DEBUG=True, CORS *, JWT alg=none (misconfig)
"""

from __future__ import annotations

from typing import Any, Dict, List

VIBE_CURATED: List[Dict[str, Any]] = [
    {
        "id": "vibe-py-plainpwd-insert",
        "language": "python",
        "cwe": "CWE-256",
        "severity": "high",
        "vulnerable_code": (
            'db.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))\n'
            "# plaintext password stored"
        ),
        "secure_code": (
            "from werkzeug.security import generate_password_hash\n"
            "hashed = generate_password_hash(password)\n"
            'db.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed))'
        ),
        "explanation": "Lưu mật khẩu plaintext — thiếu bảo mật auth phổ biến khi vibe-code.",
    },
    {
        "id": "vibe-py-plainpwd-compare",
        "language": "python",
        "cwe": "CWE-256",
        "severity": "high",
        "vulnerable_code": (
            'row = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()\n'
            'if row and row["password"] == password:\n'
            "    session['user'] = username"
        ),
        "secure_code": (
            "from werkzeug.security import check_password_hash\n"
            'row = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()\n'
            'if row and check_password_hash(row["password"], password):\n'
            "    session['user'] = username"
        ),
        "explanation": "So sánh mật khẩu plaintext thay vì check_password_hash.",
    },
    {
        "id": "vibe-py-plainpwd-dict",
        "language": "python",
        "cwe": "CWE-256",
        "severity": "high",
        "vulnerable_code": 'user_data = {"username": username, "password": password}\ndatabase.save(user_data)',
        "secure_code": (
            "from werkzeug.security import generate_password_hash\n"
            'user_data = {"username": username, "password": generate_password_hash(password)}\n'
            "database.save(user_data)"
        ),
        "explanation": "Dict user lưu field password raw.",
    },
    {
        "id": "vibe-py-weakhash-md5",
        "language": "python",
        "cwe": "CWE-327",
        "severity": "high",
        "vulnerable_code": "import hashlib\nhashed = hashlib.md5(password.encode()).hexdigest()",
        "secure_code": (
            "import bcrypt\n"
            "hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()"
        ),
        "explanation": "MD5 không phù hợp hash mật khẩu.",
    },
    {
        "id": "vibe-py-weakhash-sha256",
        "language": "python",
        "cwe": "CWE-327",
        "severity": "high",
        "vulnerable_code": "import hashlib\nreturn hashlib.sha256(password.encode()).hexdigest()",
        "secure_code": (
            "from hashlib import pbkdf2_hmac\n"
            "import os\n"
            "salt = os.urandom(16)\n"
            "return salt.hex() + ':' + pbkdf2_hmac('sha256', password.encode(), salt, 600000).hex()"
        ),
        "explanation": "SHA256 đơn không đủ work factor cho password.",
    },
    {
        "id": "vibe-py-secret-key",
        "language": "python",
        "cwe": "CWE-798",
        "severity": "high",
        "vulnerable_code": 'app = Flask(__name__)\napp.secret_key = "mynotes-student-project-key"',
        "secure_code": 'app = Flask(__name__)\napp.secret_key = os.environ["SECRET_KEY"]',
        "explanation": "Flask secret_key hardcode — session cookie dễ bị giả mạo.",
    },
    {
        "id": "vibe-py-jwt-secret",
        "language": "python",
        "cwe": "CWE-347",
        "severity": "high",
        "vulnerable_code": 'token = jwt.encode(payload, "supersecretkey", algorithm="HS256")',
        "secure_code": 'token = jwt.encode(payload, os.environ["JWT_SECRET"], algorithm="HS256")',
        "explanation": "JWT secret vibe-code hay dùng 'supersecretkey'.",
    },
    {
        "id": "vibe-py-jwt-none",
        "language": "python",
        "cwe": "CWE-347",
        "severity": "critical",
        "vulnerable_code": 'jwt.decode(token, options={"verify_signature": False})',
        "secure_code": 'jwt.decode(token, os.environ["JWT_SECRET"], algorithms=["HS256"])',
        "explanation": "Tắt verify JWT signature.",
    },
    {
        "id": "vibe-py-debug",
        "language": "python",
        "cwe": "CWE-489",
        "severity": "medium",
        "vulnerable_code": "app.run(host='0.0.0.0', port=5000, debug=True)",
        "secure_code": "app.run(host='127.0.0.1', port=5000, debug=False)",
        "explanation": "DEBUG=True trên server công khai nguy hiểm.",
    },
    {
        "id": "vibe-py-cors",
        "language": "python",
        "cwe": "CWE-942",
        "severity": "medium",
        "vulnerable_code": 'CORS(app, origins="*")',
        "secure_code": 'CORS(app, origins=["https://app.example.com"])',
        "explanation": "CORS wildcard cho mọi site gọi API.",
    },
    {
        "id": "vibe-py-db-uri",
        "language": "python",
        "cwe": "CWE-798",
        "severity": "high",
        "vulnerable_code": 'DATABASE_URL = "postgres://admin:Admin@123@localhost/shop"',
        "secure_code": 'DATABASE_URL = os.environ["DATABASE_URL"]',
        "explanation": "Connection string chứa password trong source.",
    },
    {
        "id": "vibe-js-plainpwd",
        "language": "javascript",
        "cwe": "CWE-256",
        "severity": "high",
        "vulnerable_code": (
            "await db.collection('users').insertOne({ username, password: req.body.password });"
        ),
        "secure_code": (
            "const hash = await bcrypt.hash(req.body.password, 12);\n"
            "await db.collection('users').insertOne({ username, password: hash });"
        ),
        "explanation": "Mongo insert password plaintext từ req.body.",
    },
    {
        "id": "vibe-js-plain-compare",
        "language": "javascript",
        "cwe": "CWE-256",
        "severity": "high",
        "vulnerable_code": "if (user.password === password) return done(null, user);",
        "secure_code": "if (await bcrypt.compare(password, user.password)) return done(null, user);",
        "explanation": "So sánh === với password đã hash sai — hoặc plaintext.",
    },
    {
        "id": "vibe-js-md5",
        "language": "javascript",
        "cwe": "CWE-327",
        "severity": "high",
        "vulnerable_code": "const hash = crypto.createHash('md5').update(password).digest('hex');",
        "secure_code": "const hash = await bcrypt.hash(password, 12);",
        "explanation": "MD5 cho password.",
    },
    {
        "id": "vibe-js-jwt",
        "language": "javascript",
        "cwe": "CWE-347",
        "severity": "high",
        "vulnerable_code": "jwt.sign(payload, 'supersecretkey', { expiresIn: '7d' });",
        "secure_code": "jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });",
        "explanation": "JWT secret hardcode.",
    },
    {
        "id": "vibe-js-secret-fallback",
        "language": "javascript",
        "cwe": "CWE-798",
        "severity": "high",
        "vulnerable_code": "const secret = process.env.SECRET || 'fallback-dev-secret-123456';",
        "secure_code": (
            "const secret = process.env.SECRET;\n"
            "if (!secret) throw new Error('SECRET required');"
        ),
        "explanation": "Fallback secret trong source khi thiếu env.",
    },
    {
        "id": "vibe-js-cors",
        "language": "javascript",
        "cwe": "CWE-942",
        "severity": "medium",
        "vulnerable_code": "app.use(cors({ origin: true }));",
        "secure_code": "app.use(cors({ origin: ['https://app.example.com'], credentials: true }));",
        "explanation": "origin: true phản chiếu mọi Origin.",
    },
    {
        "id": "vibe-java-plainpwd",
        "language": "java",
        "cwe": "CWE-256",
        "severity": "high",
        "vulnerable_code": (
            'User u = new User();\nu.setUsername(username);\nu.setPassword(password);\nrepo.save(u);'
        ),
        "secure_code": (
            "User u = new User();\n"
            "u.setUsername(username);\n"
            "u.setPassword(passwordEncoder.encode(password));\n"
            "repo.save(u);"
        ),
        "explanation": "Spring lưu password chưa encode.",
    },
    {
        "id": "vibe-java-md5",
        "language": "java",
        "cwe": "CWE-327",
        "severity": "high",
        "vulnerable_code": (
            "MessageDigest md = MessageDigest.getInstance(\"MD5\");\n"
            "byte[] digest = md.digest(password.getBytes());"
        ),
        "secure_code": "String hash = new BCryptPasswordEncoder().encode(password);",
        "explanation": "MD5 password hashing trong Java.",
    },
    {
        "id": "vibe-js-firebase-open",
        "language": "javascript",
        "cwe": "CWE-862",
        "severity": "critical",
        "vulnerable_code": (
            "rules_version = '2';\n"
            "service cloud.firestore {\n"
            "  match /databases/{database}/documents {\n"
            "    match /{document=**} {\n"
            "      allow read, write: if true;\n"
            "    }\n"
            "  }\n"
            "}"
        ),
        "secure_code": (
            "rules_version = '2';\n"
            "service cloud.firestore {\n"
            "  match /databases/{database}/documents {\n"
            "    match /users/{userId} {\n"
            "      allow read, write: if request.auth != null && request.auth.uid == userId;\n"
            "    }\n"
            "  }\n"
            "}"
        ),
        "explanation": "Firestore rules if true → ai cũng đọc/ghi được — lỗi vibe-code Firebase rất phổ biến.",
    },
    {
        "id": "vibe-js-jwt-decode",
        "language": "javascript",
        "cwe": "CWE-347",
        "severity": "high",
        "vulnerable_code": "const data = jwt.decode(token);\nreq.user = data;",
        "secure_code": "const data = jwt.verify(token, process.env.JWT_SECRET);\nreq.user = data;",
        "explanation": "jwt.decode không xác thực chữ ký — attacker tự tạo JWT.",
    },
    {
        "id": "vibe-js-missing-auth",
        "language": "javascript",
        "cwe": "CWE-862",
        "severity": "high",
        "vulnerable_code": "app.get('/admin/users', async (req, res) => {\n  const users = await User.find();\n  res.json(users);\n});",
        "secure_code": (
            "app.get('/admin/users', requireAuth, requireAdmin, async (req, res) => {\n"
            "  const users = await User.find();\n  res.json(users);\n});"
        ),
        "explanation": "Admin API thiếu middleware auth — Broken Access Control.",
    },
    {
        "id": "vibe-js-idor",
        "language": "javascript",
        "cwe": "CWE-639",
        "severity": "high",
        "vulnerable_code": (
            "router.get('/users/:id', async (req, res) => {\n"
            "  const u = await User.findById(req.params.id);\n"
            "  res.json(u);\n});"
        ),
        "secure_code": (
            "router.get('/users/:id', requireAuth, async (req, res) => {\n"
            "  if (String(req.user.id) !== String(req.params.id) && !req.user.isAdmin) return res.sendStatus(403);\n"
            "  const u = await User.findById(req.params.id);\n"
            "  res.json(u);\n});"
        ),
        "explanation": "IDOR: đọc user theo id mà không kiểm tra ownership.",
    },
    {
        "id": "vibe-py-jwt-decode-bare",
        "language": "python",
        "cwe": "CWE-347",
        "severity": "high",
        "vulnerable_code": "payload = jwt.decode(token)\nuser_id = payload['sub']",
        "secure_code": 'payload = jwt.decode(token, os.environ["JWT_SECRET"], algorithms=["HS256"])\nuser_id = payload["sub"]',
        "explanation": "PyJWT decode thiếu key/algorithms → không verify đúng.",
    },
]

VIBE_HARD_NEGATIVES: List[Dict[str, Any]] = [
    {
        "id": "hn-vibe-bcrypt",
        "language": "python",
        "cwe": "CWE-256",
        "code": (
            "from werkzeug.security import generate_password_hash, check_password_hash\n"
            "hashed = generate_password_hash(password)\n"
            "ok = check_password_hash(hashed, password)"
        ),
        "why_safe": "Đã dùng password hash helper.",
    },
    {
        "id": "hn-vibe-secret-env",
        "language": "python",
        "cwe": "CWE-798",
        "code": 'app.secret_key = os.environ["SECRET_KEY"]',
        "why_safe": "Secret từ môi trường.",
    },
    {
        "id": "hn-py-sqlalchemy-uri-env",
        "language": "python",
        "cwe": "CWE-798",
        "code": (
            'DB_USER = os.getenv("DB_USER")\n'
            'DB_PASSWORD = os.getenv("DB_PASSWORD")\n'
            'DATABASE_URL = f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"'
        ),
        "why_safe": "URI ghép từ biến env — không hardcode credential.",
    },
    {
        "id": "hn-py-sqlalchemy-environ",
        "language": "python",
        "cwe": "CWE-798",
        "code": 'engine = create_engine(os.environ["DATABASE_URL"])',
        "why_safe": "Connection string lấy nguyên từ env.",
    },
    {
        "id": "hn-py-getenv-secret-key",
        "language": "python",
        "cwe": "CWE-798",
        "code": 'SECRET_KEY = os.getenv("SECRET_KEY", "")\nJWT_SECRET = os.environ["JWT_SECRET"]',
        "why_safe": "Secrets từ getenv/environ.",
    },
    {
        "id": "hn-vibe-jwt-env",
        "language": "python",
        "cwe": "CWE-347",
        "code": 'jwt.encode(payload, os.environ["JWT_SECRET"], algorithm="HS256")',
        "why_safe": "JWT secret từ env.",
    },
    {
        "id": "hn-vibe-js-bcrypt",
        "language": "javascript",
        "cwe": "CWE-256",
        "code": "const hash = await bcrypt.hash(password, 12);\nif (await bcrypt.compare(password, user.password)) {}",
        "why_safe": "bcrypt hash + compare.",
    },
    {
        "id": "hn-vibe-cors-whitelist",
        "language": "javascript",
        "cwe": "CWE-942",
        "code": "app.use(cors({ origin: ['https://app.example.com'] }));",
        "why_safe": "Origin whitelist.",
    },
    {
        "id": "hn-vibe-firebase-auth",
        "language": "javascript",
        "cwe": "CWE-862",
        "code": "allow read, write: if request.auth != null && request.auth.uid == userId;",
        "why_safe": "Firebase rule binds to authenticated owner.",
    },
    {
        "id": "hn-vibe-jwt-verify",
        "language": "javascript",
        "cwe": "CWE-347",
        "code": "const data = jwt.verify(token, process.env.JWT_SECRET);",
        "why_safe": "jwt.verify with env secret.",
    },
    {
        "id": "hn-vibe-require-auth",
        "language": "javascript",
        "cwe": "CWE-862",
        "code": "app.get('/admin/users', requireAuth, requireAdmin, async (req, res) => { res.json(await User.find()); });",
        "why_safe": "Has requireAuth middleware.",
    },
]

# Bulk templates: (lang, cwe, sev, vuln, secure, expl) with {v}/{id} placeholders
VIBE_BULK = {
    "python": [
        (
            "CWE-256",
            "high",
            'user = {"username": {v}, "password": password}\ndb.save(user)',
            'user = {"username": {v}, "password": generate_password_hash(password)}\ndb.save(user)',
            "Plaintext password in user dict.",
        ),
        (
            "CWE-256",
            "high",
            'if row["password"] == password: login({v})',
            "if check_password_hash(row['password'], password): login({v})",
            "Plaintext password compare.",
        ),
        (
            "CWE-327",
            "high",
            "hashlib.md5(password.encode()).hexdigest()",
            "bcrypt.hashpw(password.encode(), bcrypt.gensalt())",
            "MD5 password hash.",
        ),
        (
            "CWE-798",
            "high",
            'app.secret_key = "supersecretkey-{id}"',
            'app.secret_key = os.environ["SECRET_KEY"]',
            "Hardcoded Flask secret_key.",
        ),
        (
            "CWE-347",
            "high",
            'jwt.encode(data, "supersecretkey", algorithm="HS256")',
            'jwt.encode(data, os.environ["JWT_SECRET"], algorithm="HS256")',
            "Hardcoded JWT secret.",
        ),
        (
            "CWE-489",
            "medium",
            "app.run(debug=True)",
            "app.run(debug=False)",
            "Flask debug mode.",
        ),
        (
            "CWE-942",
            "medium",
            'CORS(app, origins="*")',
            'CORS(app, origins=["https://frontend.example"])',
            "CORS wildcard.",
        ),
    ],
    "javascript": [
        (
            "CWE-256",
            "high",
            "await Users.create({ email: {v}, password: req.body.password })",
            "await Users.create({ email: {v}, password: await bcrypt.hash(req.body.password, 12) })",
            "Plaintext password create.",
        ),
        (
            "CWE-256",
            "high",
            "if (user.password === password) ok({v})",
            "if (await bcrypt.compare(password, user.password)) ok({v})",
            "Plaintext password ===.",
        ),
        (
            "CWE-327",
            "high",
            "crypto.createHash('md5').update(password).digest('hex')",
            "await bcrypt.hash(password, 12)",
            "MD5 password.",
        ),
        (
            "CWE-347",
            "high",
            "jwt.sign(payload, 'supersecretkey')",
            "jwt.sign(payload, process.env.JWT_SECRET)",
            "JWT hardcode.",
        ),
        (
            "CWE-798",
            "high",
            "const secret = process.env.SECRET || 'fallback-dev-secret-{id}'",
            "const secret = process.env.SECRET; if (!secret) throw new Error('missing')",
            "Secret env fallback.",
        ),
        (
            "CWE-942",
            "medium",
            "cors({ origin: true })",
            "cors({ origin: ['https://app.example'] })",
            "CORS origin true.",
        ),
        (
            "CWE-347",
            "high",
            "const payload = jwt.decode(token)",
            "const payload = jwt.verify(token, process.env.JWT_SECRET)",
            "jwt.decode without verify.",
        ),
        (
            "CWE-862",
            "critical",
            "allow read, write: if true;",
            "allow read, write: if request.auth != null && request.auth.uid == resource.data.ownerId;",
            "Firebase open security rules.",
        ),
        (
            "CWE-862",
            "high",
            "app.get('/admin/users', (req, res) => { User.find() })",
            "app.get('/admin/users', requireAuth, requireAdmin, (req, res) => { User.find() })",
            "Admin route missing auth middleware.",
        ),
        (
            "CWE-862",
            "high",
            "router.get('/users/:id', async (req, res) => { const u = await User.findById(req.params.id); res.json(u) })",
            "router.get('/users/:id', requireAuth, async (req, res) => { if (req.user.id !== req.params.id) return res.sendStatus(403); const u = await User.findById(req.params.id); res.json(u) })",
            "IDOR: fetch user by id without authz.",
        ),
    ],
}
