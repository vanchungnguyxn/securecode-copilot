"""Security rule definitions for multi-language SAST."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional
import re


@dataclass
class Rule:
    rule_id: str
    title: str
    severity: str  # critical|high|medium|low|info
    cwe: str
    owasp: str
    languages: List[str]
    patterns: List[str]
    message: str
    fix_hint: str
    secure_patterns: List[str] = field(default_factory=list)
    exclude_patterns: List[str] = field(default_factory=list)
    confidence: float = 0.88

    def compiled(self) -> List[re.Pattern]:
        return [re.compile(p, re.MULTILINE | re.IGNORECASE) for p in self.patterns]


# ---------------------------------------------------------------------------
# Python rules
# ---------------------------------------------------------------------------
PYTHON_RULES: List[Rule] = [
    Rule(
        rule_id="PY-SQLI-001",
        title="SQL Injection via string concatenation",
        severity="critical",
        cwe="CWE-89",
        owasp="A03:2021-Injection",
        languages=["python"],
        patterns=[
            r"""(?P<code>(?:execute|executemany|cursor\.execute)\s*\(\s*(?:f["']|["'].*%|["'].*\+|["'].*\.format))""",
            r"""(?P<code>(?:query|sql)\s*=\s*(?:f["'].*(?:SELECT|INSERT|UPDATE|DELETE)|["'].*(?:SELECT|INSERT|UPDATE|DELETE).*?(?:\+|%\s*\(|\.format)))""",
            r"""(?P<code>\.execute\s*\(\s*f["'])""",
        ],
        message="Truy vấn SQL được xây bằng nối chuỗi / f-string — dễ bị SQL Injection.",
        fix_hint="Dùng parameterized query / prepared statement (placeholder ? hoặc %s).",
        secure_patterns=["execute(", "?", "%s"],
    ),
    Rule(
        rule_id="PY-CMDI-001",
        title="OS Command Injection",
        severity="critical",
        cwe="CWE-78",
        owasp="A03:2021-Injection",
        languages=["python"],
        patterns=[
            r"""(?P<code>os\.system\s*\()""",
            r"""(?P<code>subprocess\.(?:call|run|Popen)\s*\([^)]*shell\s*=\s*True)""",
            r"""(?P<code>os\.popen\s*\()""",
            r"""(?P<code>commands\.(?:getoutput|getstatusoutput)\s*\()""",
        ],
        message="Thực thi lệnh hệ thống với dữ liệu người dùng có thể dẫn tới Command Injection.",
        fix_hint="Tránh shell=True; dùng list arguments và shlex.quote / whitelist.",
    ),
    Rule(
        rule_id="PY-XSS-001",
        title="Cross-Site Scripting (XSS) — unsafe HTML render",
        severity="high",
        cwe="CWE-79",
        owasp="A03:2021-Injection",
        languages=["python"],
        patterns=[
            r"""(?P<code>Markup\s*\(|bleach\.clean\s*\(|render_template_string\s*\([^)]*\+)""",
            r"""(?P<code>\|safe\b)""",
            r"""(?P<code>Response\s*\([^)]*\+|HttpResponse\s*\([^)]*\+)""",
        ],
        message="Output HTML không được escape đủ — nguy cơ XSS.",
        fix_hint="Escape HTML (jinja autoescape, html.escape) và tránh |safe với input người dùng.",
    ),
    Rule(
        rule_id="PY-PATH-001",
        title="Path Traversal",
        severity="high",
        cwe="CWE-22",
        owasp="A01:2021-Broken Access Control",
        languages=["python"],
        patterns=[
            r"""(?P<code>open\s*\(\s*(?:os\.path\.join\s*\([^)]*request|[^,\n]*request\.(?:args|form|GET|POST|json)))""",
            r"""(?P<code>open\s*\(\s*(?:f["']|["'][^"']*["']\s*\+|[a-zA-Z_][\w]*\s*\+\s*["']?/))""",
            r"""(?P<code>(?:send_file|send_from_directory)\s*\([^)]*request)""",
        ],
        message="Đường dẫn file lấy từ input người dùng — nguy cơ Path Traversal (../).",
        fix_hint="Chuẩn hoá path bằng os.path.realpath và kiểm tra prefix thư mục cho phép.",
    ),
    Rule(
        rule_id="PY-DESER-001",
        title="Insecure Deserialization (pickle/yaml)",
        severity="critical",
        cwe="CWE-502",
        owasp="A08:2021-Software and Data Integrity Failures",
        languages=["python"],
        patterns=[
            r"""(?P<code>pickle\.(?:loads?|Unpickler)\s*\()""",
            r"""(?P<code>yaml\.(?:load|unsafe_load)\s*\((?!.*Loader\s*=\s*yaml\.SafeLoader))""",
            r"""(?P<code>marshal\.loads?\s*\()""",
        ],
        message="Deserialization không an toàn có thể dẫn tới Remote Code Execution.",
        fix_hint="Dùng json hoặc yaml.safe_load; tuyệt đối tránh pickle với dữ liệu không tin cậy.",
    ),
    Rule(
        rule_id="PY-HARDCODE-001",
        title="Hardcoded secret / credential",
        severity="high",
        cwe="CWE-798",
        owasp="A07:2021-Identification and Authentication Failures",
        languages=["python"],
        patterns=[
            r"""(?P<code>(?:password|passwd|pwd|secret|api_key|apikey|access_token|private_key)\s*=\s*["'][^"']{6,}["'])""",
            r"""(?P<code>(?:secret_key|SECRET_KEY|JWT_SECRET|jwt_secret)\s*=\s*["'][^"']{4,}["'])""",
            r"""(?P<code>AWS_SECRET_ACCESS_KEY\s*=\s*["'][^"']+["'])""",
            # URI with *literal* user:pass — avoid matching inside "pymysql" and f"{VAR}" placeholders
            r"""(?P<code>(?<![A-Za-z0-9_])(?:mysql(?:\+\w+)?|postgres(?:ql)?|mongodb(?:\+\w+)?|redis)://[A-Za-z0-9._%+-]+:[^"'\s{}$/@]{3,}@)""",
        ],
        message="Credential được hard-code trong source — dễ lộ khi commit.",
        fix_hint="Đưa bí mật vào biến môi trường / secret manager.",
        exclude_patterns=[
            r'=\s*["\'](?:changeme|placeholder|xxx|your_|<.*>|\$\{|os\.environ)',
            r"\{[A-Za-z_][A-Za-z0-9_]*\}",  # f-string / format vars
            r"os\.(?:getenv|environ)",
            r"%\([A-Za-z_][\w]*\)s",
        ],
    ),
    Rule(
        rule_id="PY-PLAINPWD-001",
        title="Plaintext password storage / comparison",
        severity="high",
        cwe="CWE-256",
        owasp="A07:2021-Identification and Authentication Failures",
        languages=["python"],
        patterns=[
            r"""(?P<code>["']password["']\s*:\s*password\b)""",
            r"""(?P<code>\[[\"']password[\"']\]\s*==\s*(?:password|pwd|plain))""",
            r"""(?P<code>\[[\"']password[\"']\]\s*==\s*\w+)""",
            r"""(?P<code>(?:row|user|account)\[[\"']password[\"']\]\s*==)""",
            r"""(?P<code>\.password\s*==\s*(?:password|pwd|request\.))""",
            r"""(?P<code>INSERT\s+INTO\s+\w*\s*users?\s*\([^)]*\bpassword\b(?!_hash)[^)]*\)\s*VALUES)""",
        ],
        message="Mật khẩu được lưu hoặc so sánh dạng plaintext — vibe-code thường thiếu hash.",
        fix_hint="Hash bằng bcrypt / argon2 / scrypt; so sánh bằng check_password_hash.",
        exclude_patterns=[r"bcrypt|argon2|pbkdf2|scrypt|generate_password_hash|check_password|password_hash"],
    ),
    Rule(
        rule_id="PY-WEAKHASH-001",
        title="Weak / fast hash used for passwords",
        severity="high",
        cwe="CWE-327",
        owasp="A02:2021-Cryptographic Failures",
        languages=["python"],
        patterns=[
            r"""(?P<code>hashlib\.(?:md5|sha1)\s*\(\s*(?:password|pwd|passwd))""",
            r"""(?P<code>hashlib\.(?:md5|sha1|sha256)\s*\([^)]*password[^)]*\)\.(?:hexdigest|digest)\s*\(\s*\))""",
            r"""(?P<code>hashlib\.sha256\s*\(\s*password\.encode)""",
        ],
        message="MD5/SHA dùng để \"hash password\" không đủ (thiếu salt/work factor) — phổ biến ở code AI generate.",
        fix_hint="Dùng bcrypt / argon2id / PBKDF2-HMAC với iterations cao.",
    ),
    Rule(
        rule_id="PY-DEBUG-001",
        title="Debug mode enabled in web app",
        severity="medium",
        cwe="CWE-489",
        owasp="A05:2021-Security Misconfiguration",
        languages=["python"],
        patterns=[
            r"""(?P<code>app\.run\s*\([^)]*debug\s*=\s*True)""",
            r"""(?P<code>(?:DEBUG|FLASK_DEBUG)\s*=\s*True)""",
            r"""(?P<code>app\.config\[[\"']DEBUG[\"']\]\s*=\s*True)""",
        ],
        message="DEBUG=True lộ stacktrace / có thể cho phép code reload nguy hiểm trên production.",
        fix_hint="Tắt debug trên production; dùng biến môi trường FLASK_DEBUG=0.",
        confidence=0.75,
    ),
    Rule(
        rule_id="PY-CORS-001",
        title="Overly permissive CORS",
        severity="medium",
        cwe="CWE-942",
        owasp="A05:2021-Security Misconfiguration",
        languages=["python"],
        patterns=[
            r"""(?P<code>CORS\s*\([^)]*origins?\s*=\s*[\"']\*[\"'])""",
            r"""(?P<code>Access-Control-Allow-Origin[\"']?\s*[:=]\s*[\"']\*[\"'])""",
            r"""(?P<code>allow_origins\s*=\s*\[[\"']\*[\"']\])""",
        ],
        message="CORS cho phép mọi origin — vibe-code thường mở wildcard.",
        fix_hint="Whitelist origin cụ thể của frontend.",
        confidence=0.8,
    ),
    Rule(
        rule_id="PY-JWT-001",
        title="Insecure JWT usage",
        severity="high",
        cwe="CWE-347",
        owasp="A07:2021-Identification and Authentication Failures",
        languages=["python"],
        patterns=[
            r"""(?P<code>jwt\.encode\s*\([^)]*(?:[\"'][^\"']{6,}[\"']|secret\s*=\s*[\"']))""",
            r"""(?P<code>algorithms?\s*=\s*\[[\"']none[\"']\])""",
            r"""(?P<code>algorithms?\s*=\s*\[[^\]]*[\"']none[\"'])""",
            r"""(?P<code>jwt\.decode\s*\([^)]*options\s*=\s*\{[^}]*verify_signature[\"']?\s*:\s*False)""",
            r"""(?P<code>jwt\.decode\s*\([^)]*verify\s*=\s*False)""",
            r"""(?P<code>jwt\.decode\s*\(\s*\w+\s*\)\s*(?:#|$))""",
            r"""(?P<code>PyJWT\.decode\s*\([^)]*[\"'][^\"']{6,}[\"'])""",
        ],
        message="JWT secret hardcode, alg=none, hoặc decode không verify — vibe-code auth thường sai.",
        fix_hint="JWT_SECRET từ env; luôn verify signature + cố định algorithms; không dùng none.",
    ),
    Rule(
        rule_id="PY-AUTHZ-001",
        title="Sensitive route without auth check",
        severity="high",
        cwe="CWE-862",
        owasp="A01:2021-Broken Access Control",
        languages=["python"],
        patterns=[
            r"""(?P<code>@app\.route\s*\(\s*[\"']/(?:admin|dashboard|users|api/admin)(?!/logout)[^\"']*[\"'][^)]*\)\s*\n\s*def\s+\w+\s*\([^)]*\):\s*\n(?:(?!\n(?:.*(?:session|login_required|current_user|jwt_required|get_jwt)).*).*\n){0,3}\s*(?:return|render|jsonify))""",
            r"""(?P<code>def\s+(?:admin|delete_user|get_all_users)(?![_\w])\s*\([^)]*\):\s*\n(?:(?!.*(?:session|login_required|current_user|jwt_required)).*\n){0,2}\s*(?:return|db\.|User\.))""",
        ],
        message="Route nhạy cảm có vẻ thiếu kiểm tra session/JWT — Broken Access Control kiểu vibe-code.",
        fix_hint="Thêm @login_required / @jwt_required và kiểm tra ownership (IDOR).",
        confidence=0.65,
        exclude_patterns=[r"/logout|def admin_logout|login_required|jwt_required"],
    ),
    Rule(
        rule_id="PY-FIREBASE-001",
        title="Firebase / Firestore open or unsafe config",
        severity="critical",
        cwe="CWE-862",
        owasp="A01:2021-Broken Access Control",
        languages=["python"],
        patterns=[
            r"""(?P<code>allow\s+(?:read|write)(?:\s*,\s*(?:read|write))?\s*:\s*if\s+true\s*;)""",
            r"""(?P<code>credentials\.Certificate\s*\(\s*\{[^}]*(?:private_key|private_key_id)\s*:\s*[\"'])""",
            r"""(?P<code>FIREBASE_(?:API_KEY|PRIVATE_KEY)\s*=\s*[\"'][^\"']+[\"'])""",
        ],
        message="Firebase rules mở (if true) hoặc service-account key hardcode — truy cập trái phép / lộ khóa.",
        fix_hint="Rules: request.auth != null + ownership; private key chỉ qua env/secret manager.",
    ),
    Rule(
        rule_id="PY-SSRF-001",
        title="Server-Side Request Forgery (SSRF)",
        severity="high",
        cwe="CWE-918",
        owasp="A10:2021-SSRF",
        languages=["python"],
        patterns=[
            r"""(?P<code>requests\.(?:get|post|put|delete|head|request)\s*\(\s*(?:[^,\n]*request\.|url\s*=))""",
            r"""(?P<code>urllib\.request\.urlopen\s*\([^)]*(?:request\.|user_))""",
            r"""(?P<code>httpx\.(?:get|post|request)\s*\([^)]*request\.)""",
        ],
        message="URL lấy từ người dùng khi gọi HTTP nội bộ — nguy cơ SSRF.",
        fix_hint="Whitelist host/scheme; chặn IP private (127.0.0.1, 10.x, 169.254.x).",
    ),
    Rule(
        rule_id="PY-EVAL-001",
        title="Dangerous dynamic code execution",
        severity="critical",
        cwe="CWE-95",
        owasp="A03:2021-Injection",
        languages=["python"],
        patterns=[
            r"""(?P<code>\beval\s*\()""",
            r"""(?P<code>\bexec\s*\()""",
            r"""(?P<code>__import__\s*\([^)]*request)""",
            r"""(?P<code>compile\s*\([^)]*request)""",
        ],
        message="eval/exec với dữ liệu ngoài = Remote Code Execution.",
        fix_hint="Tránh eval/exec; dùng AST literal_eval hoặc parser an toàn.",
    ),
]

# ---------------------------------------------------------------------------
# JavaScript / TypeScript
# ---------------------------------------------------------------------------
JS_RULES: List[Rule] = [
    Rule(
        rule_id="JS-SQLI-001",
        title="SQL Injection in JS/TS",
        severity="critical",
        cwe="CWE-89",
        owasp="A03:2021-Injection",
        languages=["javascript", "typescript"],
        patterns=[
            r"""(?P<code>(?:query|execute)\s*\(\s*(?:`[^`]*\$\{|['"].*\+))""",
            r"""(?P<code>(?:connection|db|client)\.query\s*\(\s*(?:`|['"][^'"]*['"]\s*\+))""",
            r"""(?P<code>sequelize\.query\s*\(\s*`[^`]*\$\{)""",
        ],
        message="SQL được dựng bằng template string / nối chuỗi.",
        fix_hint="Dùng parameterized queries hoặc ORM bind parameters.",
    ),
    Rule(
        rule_id="JS-XSS-001",
        title="DOM XSS via innerHTML / document.write",
        severity="high",
        cwe="CWE-79",
        owasp="A03:2021-Injection",
        languages=["javascript", "typescript"],
        patterns=[
            r"""(?P<code>\.innerHTML\s*=)""",
            r"""(?P<code>\.outerHTML\s*=)""",
            r"""(?P<code>document\.write\s*\()""",
            r"""(?P<code>dangerouslySetInnerHTML)""",
        ],
        message="Ghi HTML thô từ dữ liệu có thể kiểm soát → XSS.",
        fix_hint="Dùng textContent hoặc thư viện sanitize (DOMPurify).",
    ),
    Rule(
        rule_id="JS-CMDI-001",
        title="Command Injection (child_process)",
        severity="critical",
        cwe="CWE-78",
        owasp="A03:2021-Injection",
        languages=["javascript", "typescript"],
        patterns=[
            r"""(?P<code>(?:exec|execSync)\s*\([^)]*(?:\+|`\$\{))""",
            r"""(?P<code>child_process\.(?:exec|execSync)\s*\()""",
        ],
        message="child_process.exec với input người dùng nguy hiểm.",
        fix_hint="Dùng execFile/spawn với mảng args, không shell.",
    ),
    Rule(
        rule_id="JS-EVAL-001",
        title="Use of eval / Function constructor",
        severity="critical",
        cwe="CWE-95",
        owasp="A03:2021-Injection",
        languages=["javascript", "typescript"],
        patterns=[
            r"""(?P<code>\beval\s*\()""",
            r"""(?P<code>new\s+Function\s*\()""",
            r"""(?P<code>setTimeout\s*\(\s*['"`])""",
            r"""(?P<code>setInterval\s*\(\s*['"`])""",
        ],
        message="eval / Function thực thi chuỗi động — RCE/XSS.",
        fix_hint="Không eval chuỗi từ người dùng; dùng JSON.parse cho data.",
    ),
    Rule(
        rule_id="JS-PATH-001",
        title="Path Traversal",
        severity="high",
        cwe="CWE-22",
        owasp="A01:2021-Broken Access Control",
        languages=["javascript", "typescript"],
        patterns=[
            r"""(?P<code>fs\.(?:readFile|readFileSync|createReadStream|writeFile)\s*\([^)]*(?:req\.|params\.|query\.|body\.))""",
            r"""(?P<code>path\.join\s*\([^)]*(?:req\.|params\.|query\.))""",
        ],
        message="Đường dẫn file phụ thuộc request — Path Traversal.",
        fix_hint="path.resolve + kiểm tra startsWith(baseDir).",
    ),
    Rule(
        rule_id="JS-PROTO-001",
        title="Prototype Pollution",
        severity="high",
        cwe="CWE-1321",
        owasp="A08:2021-Software and Data Integrity Failures",
        languages=["javascript", "typescript"],
        patterns=[
            r"""(?P<code>(?:__proto__|constructor\s*\[|prototype\s*\[))""",
            r"""(?P<code>Object\.assign\s*\(\s*\{\s*\}\s*,\s*(?:req\.|JSON\.parse))""",
            r"""(?P<code>lodash\.merge\s*\([^)]*req\.)""",
        ],
        message="Merge object không lọc key đặc biệt → Prototype Pollution.",
        fix_hint="Chặn __proto__, constructor, prototype; dùng Object.create(null).",
    ),
    Rule(
        rule_id="JS-HARDCODE-001",
        title="Hardcoded API key / secret",
        severity="high",
        cwe="CWE-798",
        owasp="A07:2021-Identification and Authentication Failures",
        languages=["javascript", "typescript"],
        patterns=[
            r"""(?P<code>(?:apiKey|api_key|secret|password|token|privateKey|JWT_SECRET|secretOrKey)\s*[:=]\s*['"][^'"]{6,}['"])""",
            r"""(?P<code>process\.env\.\w+\s*\|\|\s*['"][^'"]{8,}['"])""",
        ],
        message="Secret hard-code / fallback trong JS — vibe-code hay để secret trong source.",
        fix_hint="Dùng process.env (bắt buộc có); không fallback secret trong code.",
        exclude_patterns=[r"['\"](?:changeme|placeholder|your_[\w]*|xxx+|TODO)['\"]", r"example\.com"],
    ),
    Rule(
        rule_id="JS-PLAINPWD-001",
        title="Plaintext password storage / comparison",
        severity="high",
        cwe="CWE-256",
        owasp="A07:2021-Identification and Authentication Failures",
        languages=["javascript", "typescript"],
        patterns=[
            r"""(?P<code>password\s*:\s*password\b)""",
            r"""(?P<code>password\s*:\s*req\.(?:body|query)\.password)""",
            r"""(?P<code>\.password\s*===\s*(?:password|req\.|plain))""",
            r"""(?P<code>user\.password\s*===\s*)""",
        ],
        message="Lưu/so sánh mật khẩu plaintext — phổ biến ở auth do AI generate.",
        fix_hint="bcrypt.hash / argon2; so sánh bằng bcrypt.compare.",
        exclude_patterns=[r"bcrypt|argon2|scrypt|pbkdf2"],
    ),
    Rule(
        rule_id="JS-WEAKHASH-001",
        title="Weak hash for passwords (md5/sha1/sha256)",
        severity="high",
        cwe="CWE-327",
        owasp="A02:2021-Cryptographic Failures",
        languages=["javascript", "typescript"],
        patterns=[
            r"""(?P<code>createHash\s*\(\s*['"]md5['"]\s*\))""",
            r"""(?P<code>createHash\s*\(\s*['"]sha1['"]\s*\))""",
            r"""(?P<code>createHash\s*\(\s*['"]sha256['"]\s*\)[^;]{0,80}password)""",
            r"""(?P<code>md5\s*\(\s*password)""",
        ],
        message="Hash nhanh (md5/sha) không phù hợp lưu mật khẩu.",
        fix_hint="Dùng bcrypt / argon2 với cost factor đủ cao.",
    ),
    Rule(
        rule_id="JS-CORS-001",
        title="Overly permissive CORS",
        severity="medium",
        cwe="CWE-942",
        owasp="A05:2021-Security Misconfiguration",
        languages=["javascript", "typescript"],
        patterns=[
            r"""(?P<code>origin\s*:\s*true\b)""",
            r"""(?P<code>origin\s*:\s*['"]\*['"])""",
            r"""(?P<code>Access-Control-Allow-Origin['"]?\s*,\s*['"]\*['"])""",
        ],
        message="CORS mở wildcard / origin:true.",
        fix_hint="Whitelist domain frontend.",
        confidence=0.75,
    ),
    Rule(
        rule_id="JS-JWT-001",
        title="Insecure JWT usage",
        severity="high",
        cwe="CWE-347",
        owasp="A07:2021-Identification and Authentication Failures",
        languages=["javascript", "typescript"],
        patterns=[
            r"""(?P<code>jwt\.sign\s*\([^)]*['"][^'"]{6,}['"])""",
            r"""(?P<code>algorithms?\s*:\s*\[['\"]none['\"]\])""",
            r"""(?P<code>algorithms?\s*:\s*\[[^\]]*['\"]none['\"])""",
            r"""(?P<code>jwt\.verify\s*\([^)]*['"][^'"]{6,}['"])""",
            r"""(?P<code>jwt\.decode\s*\(\s*[^,\)]+\s*(?:,\s*(?:null|undefined)\s*)?\))""",
            r"""(?P<code>expiresIn\s*:\s*['"](?:365d|9999d|100y|9999h)['"])""",
        ],
        message="JWT secret hardcode, decode không verify, alg=none, hoặc hết hạn quá dài.",
        fix_hint="Secret từ process.env; luôn jwt.verify; TTL ngắn (vd. 15m–1h).",
    ),
    Rule(
        rule_id="JS-FIREBASE-001",
        title="Firebase open rules / service account leak",
        severity="critical",
        cwe="CWE-862",
        owasp="A01:2021-Broken Access Control",
        languages=["javascript", "typescript", "firebase"],
        patterns=[
            r"""(?P<code>allow\s+(?:read|write)(?:\s*,\s*(?:read|write))?\s*:\s*if\s+true\s*;)""",
            r"""(?P<code>match\s*/\{document=\*\*\}\s*\{[^}]*allow\s+read,\s*write:\s*if\s+true)""",
            r"""(?P<code>["']private_key["']\s*:\s*["']-----BEGIN)""",
            r"""(?P<code>admin\.initializeApp\s*\(\s*\{[^}]*credential:\s*admin\.credential\.cert\s*\(\s*\{)""",
        ],
        message="Firestore/Realtime rules mở toàn bộ (if true) hoặc private_key hardcode — truy cập trái phép.",
        fix_hint="allow chỉ khi request.auth != null && resource.data.uid == request.auth.uid; key qua secret.",
    ),
    Rule(
        rule_id="JS-AUTHZ-001",
        title="API route missing authentication middleware",
        severity="high",
        cwe="CWE-862",
        owasp="A01:2021-Broken Access Control",
        languages=["javascript", "typescript"],
        patterns=[
            r"""(?P<code>(?:app|router)\.(?:get|post|put|delete|patch)\s*\(\s*['"]/(?:admin|api/admin|users|api/users)[^'"]*['"]\s*,\s*(?:async\s*)?\()""",
            r"""(?P<code>(?:app|router)\.(?:get|post|put|delete)\s*\(\s*['"][^'"]+['"]\s*,\s*async\s*\(\s*req\s*,\s*res\s*\)\s*=>\s*\{[^}]{0,120}(?:findById|findOne|deleteOne)\([^)]*req\.(?:params|query))""",
        ],
        message="Endpoint nhạy cảm / thao tác theo id user nhưng không thấy auth middleware — dễ IDOR khi vibe-code.",
        fix_hint="Thêm requireAuth / passport / verifyJWT trước handler; kiểm tra ownership.",
        confidence=0.62,
        exclude_patterns=[
            r"requireAuth|authMiddleware|verifyToken|passport\.authenticate|isAuthenticated|protect\b|requireAdmin",
            r"['\"]/(?:admin/)?(?:login|logout|register|signin|signout)",
        ],
    ),
]

# ---------------------------------------------------------------------------
# Java
# ---------------------------------------------------------------------------
JAVA_RULES: List[Rule] = [
    Rule(
        rule_id="JAVA-SQLI-001",
        title="SQL Injection (Statement concatenation)",
        severity="critical",
        cwe="CWE-89",
        owasp="A03:2021-Injection",
        languages=["java"],
        patterns=[
            r"""(?P<code>Statement\s+\w+\s*=.*?\.createStatement\s*\()""",
            r"""(?P<code>\.execute(?:Query|Update)?\s*\(\s*["'][^"']*["']\s*\+)""",
            r"""(?P<code>"(?:SELECT|INSERT|UPDATE|DELETE)[^"]*"\s*\+)""",
        ],
        message="Dùng Statement nối chuỗi thay vì PreparedStatement.",
        fix_hint="Chuyển sang PreparedStatement với placeholder ?.",
    ),
    Rule(
        rule_id="JAVA-CMDI-001",
        title="Command Injection (Runtime.exec)",
        severity="critical",
        cwe="CWE-78",
        owasp="A03:2021-Injection",
        languages=["java"],
        patterns=[
            r"""(?P<code>Runtime\.getRuntime\s*\(\s*\)\s*\.exec\s*\()""",
            r"""(?P<code>new\s+ProcessBuilder\s*\([^)]*\+)""",
        ],
        message="Runtime.exec với input ngoài — Command Injection.",
        fix_hint="Dùng ProcessBuilder với list args cố định + whitelist.",
    ),
    Rule(
        rule_id="JAVA-XXE-001",
        title="XML External Entity (XXE)",
        severity="high",
        cwe="CWE-611",
        owasp="A05:2021-Security Misconfiguration",
        languages=["java"],
        patterns=[
            r"""(?P<code>DocumentBuilderFactory\.newInstance\s*\()""",
            r"""(?P<code>SAXParserFactory\.newInstance\s*\()""",
            r"""(?P<code>XMLInputFactory\.new(?:Instance|Factory)\s*\()""",
        ],
        message="XML parser mặc định có thể cho phép XXE.",
        fix_hint="Tắt external entities / DTD (FEATURE_SECURE_PROCESSING).",
    ),
    Rule(
        rule_id="JAVA-DESER-001",
        title="Insecure Java Deserialization",
        severity="critical",
        cwe="CWE-502",
        owasp="A08:2021-Software and Data Integrity Failures",
        languages=["java"],
        patterns=[
            r"""(?P<code>ObjectInputStream\s*\()""",
            r"""(?P<code>\.readObject\s*\(\s*\))""",
        ],
        message="ObjectInputStream với dữ liệu không tin cậy — RCE.",
        fix_hint="Tránh deserialize không tin cậy; dùng JSON + whitelist types.",
    ),
    Rule(
        rule_id="JAVA-PATH-001",
        title="Path Traversal",
        severity="high",
        cwe="CWE-22",
        owasp="A01:2021-Broken Access Control",
        languages=["java"],
        patterns=[
            r"""(?P<code>new\s+File\s*\([^)]*(?:request\.|getParameter|getHeader))""",
            r"""(?P<code>Paths\.get\s*\([^)]*(?:request\.|getParameter))""",
            r"""(?P<code>new\s+FileInputStream\s*\([^)]*(?:request\.|getParameter))""",
        ],
        message="Tên file từ request không kiểm tra → Path Traversal.",
        fix_hint="normalize() và đảm bảo path nằm trong thư mục gốc.",
    ),
    Rule(
        rule_id="JAVA-XSS-001",
        title="Reflected XSS in servlet/JSP",
        severity="high",
        cwe="CWE-79",
        owasp="A03:2021-Injection",
        languages=["java"],
        patterns=[
            r"""(?P<code>(?:getWriter\(\)\.print|out\.print)\s*\([^)]*getParameter)""",
            r"""(?P<code>response\.getWriter\s*\(\s*\)\s*\.(?:print|write)\s*\([^)]*request)""",
        ],
        message="Ghi response trực tiếp từ parameter — XSS.",
        fix_hint="Encode HTML (OWASP Java Encoder) trước khi ghi.",
    ),
]

# ---------------------------------------------------------------------------
# C / C++
# ---------------------------------------------------------------------------
C_RULES: List[Rule] = [
    Rule(
        rule_id="C-BOF-001",
        title="Buffer Overflow (unsafe string functions)",
        severity="critical",
        cwe="CWE-120",
        owasp="A06:2021-Vulnerable and Outdated Components",
        languages=["c", "cpp"],
        patterns=[
            r"""(?P<code>\b(?:strcpy|strcat|sprintf|gets)\s*\()""",
            r"""(?P<code>\bscanf\s*\(\s*"[^"]*%s)""",
        ],
        message="Hàm không giới hạn độ dài buffer — Buffer Overflow.",
        fix_hint="Dùng strncpy/snprintf/fgets và kiểm tra kích thước.",
    ),
    Rule(
        rule_id="C-FMT-001",
        title="Format String Vulnerability",
        severity="high",
        cwe="CWE-134",
        owasp="A03:2021-Injection",
        languages=["c", "cpp"],
        patterns=[
            r"""(?P<code>\b(?:printf|fprintf|sprintf|snprintf|syslog)\s*\(\s*[a-zA-Z_][\w]*\s*\))""",
            r"""(?P<code>\bprintf\s*\(\s*(?:user|input|buf|data|arg)\w*\s*\))""",
        ],
        message="Format string lấy từ biến người dùng — Format String bug.",
        fix_hint='Dùng printf("%s", user_input) thay vì printf(user_input).',
    ),
    Rule(
        rule_id="C-CMDI-001",
        title="Command Injection (system/popen)",
        severity="critical",
        cwe="CWE-78",
        owasp="A03:2021-Injection",
        languages=["c", "cpp"],
        patterns=[
            r"""(?P<code>\bsystem\s*\()""",
            r"""(?P<code>\bpopen\s*\()""",
        ],
        message="system()/popen() với chuỗi điều khiển từ ngoài.",
        fix_hint="Tránh shell; dùng execve với argv tách biệt.",
    ),
    Rule(
        rule_id="C-UAF-001",
        title="Potential Use-After-Free pattern",
        severity="high",
        cwe="CWE-416",
        owasp="A06:2021-Vulnerable and Outdated Components",
        languages=["c", "cpp"],
        patterns=[
            r"""(?P<code>free\s*\(\s*\w+\s*\)\s*;)""",
        ],
        message="Gọi free() — kiểm tra tiếp tục dùng con trỏ (Use-After-Free).",
        fix_hint="Gán NULL sau free; dùng RAII/smart pointers (C++).",
        confidence=0.55,
    ),
    Rule(
        rule_id="C-INT-001",
        title="Integer Overflow risk in allocation",
        severity="medium",
        cwe="CWE-190",
        owasp="A04:2021-Insecure Design",
        languages=["c", "cpp"],
        patterns=[
            r"""(?P<code>malloc\s*\(\s*\w+\s*\*\s*\w+\s*\))""",
            r"""(?P<code>new\s+\w+\s*\[\s*\w+\s*\*\s*\w+\s*\])""",
        ],
        message="Phép nhân kích thước trước malloc có thể overflow.",
        fix_hint="Kiểm tra overflow trước khi cấp phát (hoặc dùng calloc an toàn).",
        confidence=0.7,
    ),
    Rule(
        rule_id="C-SQLI-001",
        title="SQL built via sprintf concatenation",
        severity="critical",
        cwe="CWE-89",
        owasp="A03:2021-Injection",
        languages=["c", "cpp"],
        patterns=[
            r"""(?P<code>sprintf\s*\([^)]*(?:SELECT|INSERT|UPDATE|DELETE))""",
            r"""(?P<code>snprintf\s*\([^)]*(?:SELECT|INSERT|UPDATE|DELETE))""",
        ],
        message="SQL được build bằng sprintf — SQL Injection.",
        fix_hint="Dùng prepared statements của sqlite3/libpq.",
    ),
]


# ---------------------------------------------------------------------------
# PHP
# ---------------------------------------------------------------------------
PHP_RULES: List[Rule] = [
    Rule(
        rule_id="PHP-SQLI-001",
        title="SQL Injection (string concat / interpolation)",
        severity="critical",
        cwe="CWE-89",
        owasp="A03:2021-Injection",
        languages=["php"],
        patterns=[
            r"""(?P<code>(?:mysqli_query|mysql_query|pg_query)\s*\([^;]*(?:\$|_GET|_POST|_REQUEST))""",
            r"""(?P<code>\$(?:sql|query)\s*=\s*["'][^"']*(?:SELECT|INSERT|UPDATE|DELETE)[^"']*["']\s*\.\s*\$)""",
            r"""(?P<code>"(?:SELECT|INSERT|UPDATE|DELETE)[^"]*"\s*\.\s*\$(?:_GET|_POST|_REQUEST|\w+))""",
            r"""(?P<code>->query\s*\(\s*["'][^"']*\$)""",
        ],
        message="SQL nối chuỗi / nội suy biến request — SQL Injection phổ biến ở PHP.",
        fix_hint="Prepared statements (PDO bindParam / mysqli_prepare).",
    ),
    Rule(
        rule_id="PHP-CMDI-001",
        title="OS Command Injection",
        severity="critical",
        cwe="CWE-78",
        owasp="A03:2021-Injection",
        languages=["php"],
        patterns=[
            r"""(?P<code>\b(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\()""",
            r"""(?P<code>`[^`]*\$(?:_GET|_POST|_REQUEST|\w+)[^`]*`)""",
        ],
        message="Thực thi lệnh shell với input có thể bị chèn — Command Injection.",
        fix_hint="Tránh shell; dùng API thư viện; escapeshellarg nếu bắt buộc.",
    ),
    Rule(
        rule_id="PHP-XSS-001",
        title="Cross-Site Scripting (unescaped echo)",
        severity="high",
        cwe="CWE-79",
        owasp="A03:2021-Injection",
        languages=["php"],
        patterns=[
            r"""(?P<code>\becho\s+\$_(?:GET|POST|REQUEST|COOKIE)\[)""",
            r"""(?P<code>\bprint\s+\$_(?:GET|POST|REQUEST)\[)""",
            r"""(?P<code>\?>\s*<\?=\s*\$_(?:GET|POST|REQUEST))""",
        ],
        message="In trực tiếp input người dùng — XSS.",
        fix_hint="htmlspecialchars($v, ENT_QUOTES, 'UTF-8') trước khi echo.",
    ),
    Rule(
        rule_id="PHP-DESER-001",
        title="Insecure deserialization (unserialize)",
        severity="critical",
        cwe="CWE-502",
        owasp="A08:2021-Software and Data Integrity Failures",
        languages=["php"],
        patterns=[
            r"""(?P<code>\bunserialize\s*\()""",
        ],
        message="unserialize dữ liệu không tin cậy có thể dẫn tới RCE / object injection.",
        fix_hint="Dùng json_decode; hoặc unserialize với allowed_classes.",
    ),
    Rule(
        rule_id="PHP-EVAL-001",
        title="Dangerous eval / create_function",
        severity="critical",
        cwe="CWE-95",
        owasp="A03:2021-Injection",
        languages=["php"],
        patterns=[
            r"""(?P<code>\beval\s*\()""",
            r"""(?P<code>\bassert\s*\(\s*\$)""",
            r"""(?P<code>\bcreate_function\s*\()""",
        ],
        message="eval/assert động — Remote Code Execution.",
        fix_hint="Không eval input; dùng cấu trúc dữ liệu / whitelist.",
    ),
    Rule(
        rule_id="PHP-HARDCODE-001",
        title="Hardcoded secret / password",
        severity="high",
        cwe="CWE-798",
        owasp="A07:2021-Identification and Authentication Failures",
        languages=["php"],
        patterns=[
            r"""(?P<code>\$(?:password|passwd|api_key|secret|db_pass)\s*=\s*['"][^'"]{6,}['"])""",
            r"""(?P<code>['"]password['"]\s*=>\s*['"][^'"]{6,}['"])""",
        ],
        message="Credential hard-code trong PHP source.",
        fix_hint="Đưa vào getenv / .env (không commit secret).",
    ),
    Rule(
        rule_id="PHP-PATH-001",
        title="Path Traversal / LFI",
        severity="high",
        cwe="CWE-22",
        owasp="A01:2021-Broken Access Control",
        languages=["php"],
        patterns=[
            r"""(?P<code>\b(?:include|require|include_once|require_once)\s*\(\s*\$_(?:GET|POST|REQUEST))""",
            r"""(?P<code>\bfile_get_contents\s*\(\s*\$_(?:GET|POST|REQUEST))""",
            r"""(?P<code>\breadfile\s*\(\s*\$_(?:GET|POST|REQUEST))""",
        ],
        message="Include/read file từ request — LFI / Path Traversal.",
        fix_hint="Whitelist tên file; realpath + kiểm tra thư mục gốc.",
    ),
]


# ---------------------------------------------------------------------------
# C#
# ---------------------------------------------------------------------------
CSHARP_RULES: List[Rule] = [
    Rule(
        rule_id="CS-SQLI-001",
        title="SQL Injection (string concat)",
        severity="critical",
        cwe="CWE-89",
        owasp="A03:2021-Injection",
        languages=["csharp"],
        patterns=[
            r"""(?P<code>(?:SqlCommand|ExecuteReader|ExecuteNonQuery)\s*\([^;]*\+)""",
            r"""(?P<code>\"(?:SELECT|INSERT|UPDATE|DELETE)[^\"]*\"\s*\+)""",
            r"""(?P<code>\$\"(?:SELECT|INSERT|UPDATE|DELETE)[^\"]*\{)""",
        ],
        message="SQL nối chuỗi / interpolation — SQL Injection trong C#.",
        fix_hint="Parameterized SqlCommand + Parameters.Add.",
    ),
    Rule(
        rule_id="CS-CMDI-001",
        title="Command Injection (Process.Start)",
        severity="critical",
        cwe="CWE-78",
        owasp="A03:2021-Injection",
        languages=["csharp"],
        patterns=[
            r"""(?P<code>Process\.Start\s*\([^)]*\+)""",
            r"""(?P<code>UseShellExecute\s*=\s*true)""",
            r"""(?P<code>new\s+ProcessStartInfo\s*\([^)]*\+)""",
        ],
        message="Process.Start với chuỗi động / shell — Command Injection.",
        fix_hint="FileName + Arguments tách; UseShellExecute=false; whitelist.",
    ),
    Rule(
        rule_id="CS-DESER-001",
        title="Insecure deserialization (BinaryFormatter)",
        severity="critical",
        cwe="CWE-502",
        owasp="A08:2021-Software and Data Integrity Failures",
        languages=["csharp"],
        patterns=[
            r"""(?P<code>new\s+BinaryFormatter\s*\()""",
            r"""(?P<code>BinaryFormatter\s*\(\s*\)\s*\.Deserialize)""",
            r"""(?P<code>JavaScriptSerializer\s*\(\s*\)\.Deserialize)""",
        ],
        message="BinaryFormatter Deserialize không tin cậy — RCE.",
        fix_hint="Dùng System.Text.Json; tránh BinaryFormatter.",
    ),
    Rule(
        rule_id="CS-XSS-001",
        title="XSS via Response.Write / Html.Raw",
        severity="high",
        cwe="CWE-79",
        owasp="A03:2021-Injection",
        languages=["csharp"],
        patterns=[
            r"""(?P<code>Response\.Write\s*\([^)]*Request)""",
            r"""(?P<code>Html\.Raw\s*\()""",
            r"""(?P<code>@Html\.Raw\s*\()""",
        ],
        message="Ghi HTML thô từ request — XSS.",
        fix_hint="HtmlEncode / tag helper encode mặc định.",
    ),
    Rule(
        rule_id="CS-HARDCODE-001",
        title="Hardcoded secret / connection string",
        severity="high",
        cwe="CWE-798",
        owasp="A07:2021-Identification and Authentication Failures",
        languages=["csharp"],
        patterns=[
            r"""(?P<code>(?:Password|ApiKey|Secret|ConnectionString)\s*=\s*\"[^\"]{8,}\")""",
            r"""(?P<code>\"(?:Password|pwd)=[^\";]{4,})""",
        ],
        message="Secret / connection string hard-code trong C#.",
        fix_hint="User Secrets / môi trường / Key Vault.",
    ),
    Rule(
        rule_id="CS-PATH-001",
        title="Path Traversal",
        severity="high",
        cwe="CWE-22",
        owasp="A01:2021-Broken Access Control",
        languages=["csharp"],
        patterns=[
            r"""(?P<code>File\.(?:ReadAllText|Open|OpenRead)\s*\([^)]*Request)""",
            r"""(?P<code>Path\.Combine\s*\([^)]*Request\.(?:Query|Form))""",
        ],
        message="Đường dẫn file từ request không kiểm soát.",
        fix_hint="GetFullPath + đảm bảo prefix thư mục gốc.",
    ),
]


# Extra C++ oriented (in addition to shared C rules)
CPP_EXTRA_RULES: List[Rule] = [
    Rule(
        rule_id="CPP-CMDI-001",
        title="Command Injection (std::system)",
        severity="critical",
        cwe="CWE-78",
        owasp="A03:2021-Injection",
        languages=["cpp"],
        patterns=[
            r"""(?P<code>std::system\s*\()""",
            r"""(?P<code>\bsystem\s*\(\s*(?:cmd|command|user|input))""",
        ],
        message="std::system với chuỗi ngoài — Command Injection.",
        fix_hint="Tránh system; dùng exec family / thư viện không shell.",
    ),
]


ALL_RULES: List[Rule] = (
    PYTHON_RULES + JS_RULES + JAVA_RULES + C_RULES + CPP_EXTRA_RULES + PHP_RULES + CSHARP_RULES
)


def rules_for_language(language: str) -> List[Rule]:
    lang = language.lower()
    if lang == "typescript":
        lang = "javascript"
    if lang in {"firebase", "firestore", "rules"}:
        lang = "firebase"
    if lang in {"c++", "cplusplus"}:
        lang = "cpp"
    if lang in {"c#", "cs"}:
        lang = "csharp"
    return [r for r in ALL_RULES if lang in r.languages or (lang == "javascript" and "typescript" in r.languages)]


def detect_language(code: str, filename: Optional[str] = None) -> str:
    if filename:
        ext = filename.rsplit(".", 1)[-1].lower()
        mapping = {
            "py": "python",
            "js": "javascript",
            "jsx": "javascript",
            "ts": "typescript",
            "tsx": "typescript",
            "java": "java",
            "c": "c",
            "h": "c",
            "cpp": "cpp",
            "cc": "cpp",
            "cxx": "cpp",
            "hpp": "cpp",
            "cs": "csharp",
            "php": "php",
            "rules": "firebase",
        }
        base = filename.replace("\\", "/").rsplit("/", 1)[-1].lower()
        if "firestore.rules" in base or "database.rules" in base or "storage.rules" in base:
            return "firebase"
        if ext in mapping:
            return mapping[ext]

    hints = [
        ("python", [r"^\s*def\s+\w+\s*\(", r"^\s*import\s+\w+", r"^\s*from\s+\w+\s+import", r"if __name__ == ['\"]__main__['\"]"]),
        ("java", [r"\bpublic\s+class\b", r"\bSystem\.out\.println\b", r"\bimport\s+java\."]),
        ("csharp", [r"\busing\s+System\b", r"\bnamespace\s+\w+", r"\bConsole\.WriteLine\b", r"\bstring\[\]\s+args\b"]),
        ("php", [r"<\?php", r"\$_GET\b", r"\$_POST\b", r"\bfunction\s+\w+\s*\("]),
        ("javascript", [r"\bconsole\.log\b", r"\brequire\s*\(", r"\bmodule\.exports\b", r"\bconst\s+\w+\s*=\s*require"]),
        ("typescript", [r"\binterface\s+\w+", r":\s*(?:string|number|boolean)\b", r"\bexport\s+(?:type|interface)\b"]),
        ("cpp", [r"#include\s*<iostream>", r"\bstd::", r"\bnamespace\s+\w+"]),
        ("c", [r"#include\s*<stdio\.h>", r"\bprintf\s*\(", r"\bmalloc\s*\("]),
    ]
    scores = {}
    for lang, pats in hints:
        score = sum(1 for p in pats if re.search(p, code, re.M))
        if score:
            scores[lang] = score
    if not scores:
        return "python"
    return max(scores, key=scores.get)
