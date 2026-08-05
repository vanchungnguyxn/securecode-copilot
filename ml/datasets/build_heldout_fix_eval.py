"""
Build held-out fix-evaluation set, disjoint from CodeT5 training SFT.

Outputs:
  ml/datasets/processed/fix_eval_heldout.jsonl
  ml/datasets/processed/fix_eval_heldout_meta.json

Sources:
  1) Curated executable Python vignettes (unit + security + functional tests)
  2) CVEFixes pairs whose vulnerable fingerprint is NOT in sft_fix.jsonl

Usage:
  python ml/datasets/build_heldout_fix_eval.py
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Set

HERE = Path(__file__).resolve().parent
PROC = HERE / "processed"

from heldout_executable_extra import EXTRA_EXECUTABLE  # noqa: E402


def norm_ws(s: str) -> str:
    return re.sub(r"\s+", "", (s or "").strip())


def fingerprint(code: str) -> str:
    return hashlib.sha1(norm_ws(code).encode("utf-8")).hexdigest()


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def train_fingerprints(sft_fix: Path) -> Set[str]:
    fps: Set[str] = set()
    for row in load_jsonl(sft_fix):
        if row.get("task") != "fix":
            continue
        inp = row.get("input") or ""
        m = re.search(r"Vulnerable code:\n([\s\S]+)$", inp)
        code = m.group(1) if m else inp
        fps.add(fingerprint(code))
        if row.get("output"):
            fps.add(fingerprint(row["output"]))
    return fps


def train_cve_ids(sft_fix: Path, pairs_path: Path) -> Set[str]:
    """Best-effort: map train fingerprints back to CVEFixes ids."""
    fps = train_fingerprints(sft_fix)
    ids: Set[str] = set()
    for p in load_jsonl(pairs_path):
        if fingerprint(p.get("vulnerable_code") or "") in fps:
            if p.get("cve_id"):
                ids.add(str(p["cve_id"]))
            if p.get("id"):
                ids.add(str(p["id"]))
    return ids


# ---------------------------------------------------------------------------
# Curated executable held-out cases (NOT from expand_sft templates verbatim)
# Each vignette is self-contained: module-level API under test.
# ---------------------------------------------------------------------------

CURATED_EXECUTABLE: List[Dict[str, Any]] = [
    {
        "id": "ho-py-sqli-order-table",
        "language": "python",
        "cwe": "CWE-89",
        "title": "Order lookup SQLi via f-string",
        "vulnerable_code": (
            "def get_order(db, order_id):\n"
            "    q = f\"SELECT * FROM orders WHERE id = {order_id}\"\n"
            "    return db.execute(q)\n"
        ),
        "secure_reference": (
            "def get_order(db, order_id):\n"
            '    return db.execute("SELECT * FROM orders WHERE id = ?", (order_id,))\n'
        ),
        "unit_tests": (
            "class FakeDB:\n"
            "    def __init__(self):\n"
            "        self.calls = []\n"
            "    def execute(self, *a):\n"
            "        self.calls.append(a)\n"
            "        return {'ok': True, 'args': a}\n"
            "db = FakeDB()\n"
            "assert get_order(db, 7)['ok']\n"
            "assert db.calls, 'must call db'\n"
        ),
        "security_tests": (
            "class FakeDB:\n"
            "    def __init__(self):\n"
            "        self.calls = []\n"
            "    def execute(self, *a):\n"
            "        self.calls.append(a)\n"
            "        return a\n"
            "db = FakeDB()\n"
            "get_order(db, \"1 OR 1=1\")\n"
            "call = db.calls[0]\n"
            "assert len(call) >= 2, 'parameterized execute required'\n"
            "sql = call[0]\n"
            "assert 'OR 1=1' not in str(sql), 'payload must not be inlined into SQL'\n"
            "assert '?' in sql or '%s' in sql\n"
        ),
        "functional_tests": (
            "class FakeDB:\n"
            "    def execute(self, *a):\n"
            "        return ('row', a[-1] if len(a)>1 else None)\n"
            "assert get_order(FakeDB(), 42)[1] == (42,) or get_order(FakeDB(), 42)[1] == 42\n"
        ),
        "forbidden_patterns": [r"f[\"'].*SELECT", r"execute\([^)]*\+"],
        "required_patterns": [],
    },
    {
        "id": "ho-py-cmdi-backup",
        "language": "python",
        "cwe": "CWE-78",
        "title": "Backup path OS command injection",
        "vulnerable_code": (
            "import os\n"
            "def backup_dir(path):\n"
            "    return os.system(\"tar -czf /tmp/b.tgz \" + path)\n"
        ),
        "secure_reference": (
            "import subprocess\n"
            "def backup_dir(path):\n"
            "    return subprocess.run([\"tar\", \"-czf\", \"/tmp/b.tgz\", path], check=False).returncode\n"
        ),
        "unit_tests": (
            "import builtins\n"
            "called = {}\n"
            "def fake_run(cmd, check=False):\n"
            "    called['cmd'] = cmd\n"
            "    class R: returncode = 0\n"
            "    return R()\n"
            "subprocess.run = fake_run\n"
            "assert backup_dir('/data/x') == 0\n"
            "assert isinstance(called['cmd'], list)\n"
        ),
        "security_tests": (
            "import subprocess as sp\n"
            "seen = {}\n"
            "def fake_run(cmd, check=False):\n"
            "    seen['cmd'] = cmd\n"
            "    class R: returncode = 0\n"
            "    return R()\n"
            "sp.run = fake_run\n"
            "subprocess.run = fake_run\n"
            "backup_dir('a; rm -rf /')\n"
            "assert isinstance(seen.get('cmd'), list), 'must use argv list, not shell string'\n"
            "assert all(';' not in str(x) or x == seen['cmd'][-1] for x in seen['cmd'][:-1] or [''])\n"
            "joined = ' '.join(map(str, seen['cmd']))\n"
            "assert 'rm -rf' not in joined.split()[0:3]\n"
        ),
        "functional_tests": (
            "seen = {}\n"
            "def fake_run(cmd, check=False):\n"
            "    seen['cmd'] = cmd\n"
            "    class R: returncode = 0\n"
            "    return R()\n"
            "subprocess.run = fake_run\n"
            "backup_dir('/var/app')\n"
            "assert seen['cmd'][-1] == '/var/app'\n"
        ),
        "forbidden_patterns": [r"os\.system", r"shell\s*=\s*True"],
        "required_patterns": [],
    },
    {
        "id": "ho-py-path-read",
        "language": "python",
        "cwe": "CWE-22",
        "title": "Path traversal on profile read",
        "vulnerable_code": (
            "def read_profile(name):\n"
            "    return open('/var/profiles/' + name).read()\n"
        ),
        "secure_reference": (
            "from pathlib import Path\n"
            "ROOT = Path('/var/profiles').resolve()\n"
            "def read_profile(name):\n"
            "    p = (ROOT / name).resolve()\n"
            "    if not str(p).startswith(str(ROOT)):\n"
            "        raise ValueError('path traversal')\n"
            "    return p.read_text()\n"
        ),
        "unit_tests": (
            "from pathlib import Path\n"
            "import tempfile, os\n"
            "td = tempfile.mkdtemp()\n"
            "globals()['ROOT'] = Path(td).resolve()\n"
            "(ROOT / 'alice.txt').write_text('hi', encoding='utf-8')\n"
            "assert 'hi' in read_profile('alice.txt')\n"
        ),
        "security_tests": (
            "from pathlib import Path\n"
            "import tempfile\n"
            "td = tempfile.mkdtemp()\n"
            "globals()['ROOT'] = Path(td).resolve()\n"
            "(ROOT / 'ok.txt').write_text('x', encoding='utf-8')\n"
            "raised = False\n"
            "try:\n"
            "    read_profile('../' + 'ok.txt')\n"
            "except Exception:\n"
            "    raised = True\n"
            "# either blocked or resolved still inside root without escape payload success\n"
            "esc = False\n"
            "try:\n"
            "    read_profile('../../../../etc/passwd')\n"
            "    esc = True\n"
            "except Exception:\n"
            "    esc = False\n"
            "assert not esc, 'must not read outside root'\n"
        ),
        "functional_tests": (
            "from pathlib import Path\n"
            "import tempfile\n"
            "td = tempfile.mkdtemp()\n"
            "globals()['ROOT'] = Path(td).resolve()\n"
            "(ROOT / 'bob.txt').write_text('bob', encoding='utf-8')\n"
            "assert read_profile('bob.txt') == 'bob'\n"
        ),
        "forbidden_patterns": [r"open\(['\"]/.+\+"],
        "required_patterns": [],
    },
    {
        "id": "ho-py-deser-pickle",
        "language": "python",
        "cwe": "CWE-502",
        "title": "Unsafe pickle loads on user blob",
        "vulnerable_code": (
            "import pickle\n"
            "def load_state(blob):\n"
            "    return pickle.loads(blob)\n"
        ),
        "secure_reference": (
            "import json\n"
            "def load_state(blob):\n"
            "    if isinstance(blob, bytes):\n"
            "        blob = blob.decode('utf-8')\n"
            "    return json.loads(blob)\n"
        ),
        "unit_tests": (
            "import json\n"
            "assert load_state(json.dumps({'a': 1}))['a'] == 1\n"
            "assert load_state(b'{\"a\": 2}')['a'] == 2\n"
        ),
        "security_tests": (
            "import inspect\n"
            "text = inspect.getsource(load_state)\n"
            "assert 'pickle' not in text, 'pickle must not be used'\n"
            "assert 'json.loads' in text or 'json.load' in text\n"
        ),
        "functional_tests": (
            "import json\n"
            "assert load_state('{\"k\": \"v\"}') == {'k': 'v'}\n"
        ),
        "forbidden_patterns": [r"pickle\.loads", r"pickle\.load"],
        "required_patterns": [r"json\.loads"],
    },
    {
        "id": "ho-py-eval-math",
        "language": "python",
        "cwe": "CWE-95",
        "title": "Eval on calculator expression",
        "vulnerable_code": (
            "def calc(expr):\n"
            "    return eval(expr)\n"
        ),
        "secure_reference": (
            "import ast\n"
            "def calc(expr):\n"
            "    return ast.literal_eval(expr)\n"
        ),
        "unit_tests": (
            "assert calc('1') == 1\n"
            "assert calc(\"{'x': 2}\")['x'] == 2\n"
        ),
        "security_tests": (
            "import inspect\n"
            "text = inspect.getsource(calc)\n"
            "assert 'eval(' not in text.replace('literal_eval', '')\n"
            "bad = False\n"
            "try:\n"
            "    calc('__import__(\"os\").system(\"echo pwn\")')\n"
            "    bad = True\n"
            "except Exception:\n"
            "    bad = False\n"
            "assert not bad\n"
        ),
        "functional_tests": "assert calc('[1,2,3]') == [1,2,3]\n",
        "forbidden_patterns": [r"(?<!literal_)eval\("],
        "required_patterns": [r"literal_eval"],
    },
    {
        "id": "ho-py-secret-jwt",
        "language": "python",
        "cwe": "CWE-798",
        "title": "Hardcoded JWT secret fallback",
        "vulnerable_code": (
            "import os\n"
            "SECRET = os.getenv('JWT_SECRET') or 'super-secret-dev-key'\n"
            "def get_secret():\n"
            "    return SECRET\n"
        ),
        "secure_reference": (
            "import os\n"
            "def get_secret():\n"
            "    v = os.getenv('JWT_SECRET')\n"
            "    if not v:\n"
            "        raise RuntimeError('JWT_SECRET required')\n"
            "    return v\n"
        ),
        "unit_tests": (
            "import os\n"
            "os.environ['JWT_SECRET'] = 'abc123'\n"
            "assert get_secret() == 'abc123'\n"
        ),
        "security_tests": (
            "import os, inspect\n"
            "text = inspect.getsource(get_secret) + inspect.getsource(get_secret.__globals__.get('get_secret', get_secret))\n"
            "text = inspect.getsource(get_secret)\n"
            "assert 'super-secret' not in text\n"
            "os.environ.pop('JWT_SECRET', None)\n"
            "raised = False\n"
            "try:\n"
            "    get_secret()\n"
            "except Exception:\n"
            "    raised = True\n"
            "assert raised, 'must fail closed without env'\n"
        ),
        "functional_tests": (
            "import os\n"
            "os.environ['JWT_SECRET'] = 'tok'\n"
            "assert isinstance(get_secret(), str) and len(get_secret()) > 0\n"
        ),
        "forbidden_patterns": [r"or\s+['\"]super-secret", r"or\s+['\"][^'\"]+['\"]"],
        "required_patterns": [],
    },
    {
        "id": "ho-py-yaml-load",
        "language": "python",
        "cwe": "CWE-502",
        "title": "Unsafe loader (yaml.load-style via eval)",
        "vulnerable_code": (
            "def parse_cfg(text):\n"
            "    return eval(text)\n"
        ),
        "secure_reference": (
            "import json\n"
            "def parse_cfg(text):\n"
            "    return json.loads(text)\n"
        ),
        "unit_tests": "assert parse_cfg('{\"a\": 1}')['a'] == 1\n",
        "security_tests": (
            "import inspect\n"
            "text = inspect.getsource(parse_cfg)\n"
            "assert 'eval(' not in text\n"
            "bad=False\n"
            "try:\n"
            "    parse_cfg('__import__(\"os\").system(\"echo x\")')\n"
            "    bad=True\n"
            "except Exception:\n"
            "    bad=False\n"
            "assert not bad\n"
        ),
        "functional_tests": "assert parse_cfg('{\"k\": \"v\"}')['k'] == 'v'\n",
        "forbidden_patterns": [r"\beval\("],
        "required_patterns": [r"json\.loads|safe_load|literal_eval"],
    },
    {
        "id": "ho-py-md5-password",
        "language": "python",
        "cwe": "CWE-328",
        "title": "MD5 password hash",
        "vulnerable_code": (
            "import hashlib\n"
            "def hash_password(pw):\n"
            "    return hashlib.md5(pw.encode()).hexdigest()\n"
        ),
        "secure_reference": (
            "import hashlib\n"
            "def hash_password(pw):\n"
            "    return hashlib.sha256(pw.encode()).hexdigest()\n"
        ),
        "unit_tests": (
            "h = hash_password('x')\n"
            "assert isinstance(h, str) and len(h) == 64\n"
        ),
        "security_tests": (
            "import inspect\n"
            "text = inspect.getsource(hash_password)\n"
            "assert 'md5' not in text.lower()\n"
            "assert 'sha256' in text.lower() or 'pbkdf2' in text.lower() or 'bcrypt' in text.lower()\n"
        ),
        "functional_tests": "assert hash_password('a') == hash_password('a')\n",
        "forbidden_patterns": [r"md5"],
        "required_patterns": [],
    },
    {
        "id": "ho-py-ssh-auto-add",
        "language": "python",
        "cwe": "CWE-295",
        "title": "Paramiko AutoAddPolicy",
        "vulnerable_code": (
            "class SSHClient:\n"
            "    def set_missing_host_key_policy(self, p): self.policy = p\n"
            "    def connect(self, *a, **k): return True\n"
            "class AutoAddPolicy: pass\n"
            "class RejectPolicy: pass\n"
            "def connect(host, user, pwd):\n"
            "    c = SSHClient()\n"
            "    c.set_missing_host_key_policy(AutoAddPolicy())\n"
            "    c.connect(host, username=user, password=pwd)\n"
            "    return c\n"
        ),
        "secure_reference": (
            "class SSHClient:\n"
            "    def set_missing_host_key_policy(self, p): self.policy = p\n"
            "    def connect(self, *a, **k): return True\n"
            "    def load_system_host_keys(self): pass\n"
            "class AutoAddPolicy: pass\n"
            "class RejectPolicy: pass\n"
            "def connect(host, user, pwd):\n"
            "    c = SSHClient()\n"
            "    c.load_system_host_keys()\n"
            "    c.set_missing_host_key_policy(RejectPolicy())\n"
            "    c.connect(host, username=user, password=pwd)\n"
            "    return c\n"
        ),
        "unit_tests": (
            "c = connect('h', 'u', 'p')\n"
            "assert isinstance(c.policy, RejectPolicy)\n"
        ),
        "security_tests": (
            "import inspect\n"
            "text = inspect.getsource(connect)\n"
            "assert 'AutoAddPolicy' not in text\n"
            "assert 'RejectPolicy' in text\n"
        ),
        "functional_tests": "assert connect('h','u','p') is not None\n",
        "forbidden_patterns": [r"AutoAddPolicy"],
        "required_patterns": [r"RejectPolicy"],
    },
    {
        "id": "ho-py-flask-debug",
        "language": "python",
        "cwe": "CWE-489",
        "title": "Flask debug True in production entry",
        "vulnerable_code": (
            "class App:\n"
            "    def run(self, debug=False): self.debug = debug\n"
            "app = App()\n"
            "def run():\n"
            "    app.run(debug=True)\n"
        ),
        "secure_reference": (
            "class App:\n"
            "    def run(self, debug=False): self.debug = debug\n"
            "app = App()\n"
            "def run():\n"
            "    app.run(debug=False)\n"
        ),
        "unit_tests": (
            "run()\n"
            "assert app.debug is False\n"
        ),
        "security_tests": (
            "import inspect\n"
            "text = inspect.getsource(run)\n"
            "assert 'debug=True' not in text\n"
        ),
        "functional_tests": "run(); assert hasattr(app, 'debug')\n",
        "forbidden_patterns": [r"debug\s*=\s*True"],
        "required_patterns": [],
    },
    {
        "id": "ho-py-sql-percent",
        "language": "python",
        "cwe": "CWE-89",
        "title": "Percent-format SQL",
        "vulnerable_code": (
            "def find_user(cur, name):\n"
            "    cur.execute(\"SELECT * FROM users WHERE name = '%s'\" % name)\n"
            "    return cur.fetchone()\n"
        ),
        "secure_reference": (
            "def find_user(cur, name):\n"
            "    cur.execute(\"SELECT * FROM users WHERE name = %s\", (name,))\n"
            "    return cur.fetchone()\n"
        ),
        "unit_tests": (
            "class C:\n"
            "    def __init__(self):\n"
            "        self.q=None; self.a=None\n"
            "    def execute(self, q, a=None):\n"
            "        self.q, self.a = q, a\n"
            "    def fetchone(self):\n"
            "        return {'name': (self.a or [None])[0]}\n"
            "c=C(); assert find_user(c,'ada')['name']=='ada'\n"
        ),
        "security_tests": (
            "class C:\n"
            "    def __init__(self):\n"
            "        self.q=None; self.a=None\n"
            "    def execute(self, q, a=None):\n"
            "        self.q, self.a = q, a\n"
            "    def fetchone(self):\n"
            "        return 1\n"
            "c=C(); find_user(c, \"x' OR '1'='1\")\n"
            "assert c.a is not None and \"OR\" not in str(c.q)\n"
            "assert '%s' in c.q and \"'%s'\" not in c.q.replace('%s','')\n"
        ),
        "functional_tests": (
            "class C:\n"
            "    def execute(self, q, a=None): self.a=a\n"
            "    def fetchone(self): return self.a\n"
            "assert find_user(C(), 'z') == ('z',)\n"
        ),
        "forbidden_patterns": [r"%\s*name", r"'\s*%\s*s\s*'"],
        "required_patterns": [],
    },
    {
        "id": "ho-py-subprocess-shell",
        "language": "python",
        "cwe": "CWE-78",
        "title": "shell=True with user arg",
        "vulnerable_code": (
            "import subprocess\n"
            "def list_files(user_path):\n"
            "    return subprocess.check_output('ls ' + user_path, shell=True)\n"
        ),
        "secure_reference": (
            "import subprocess\n"
            "def list_files(user_path):\n"
            "    return subprocess.check_output(['ls', user_path])\n"
        ),
        "unit_tests": (
            "import subprocess\n"
            "seen={}\n"
            "def fake(cmd, shell=False):\n"
            "    seen['cmd']=cmd; seen['shell']=shell\n"
            "    return b'ok'\n"
            "subprocess.check_output = fake\n"
            "assert list_files('/tmp') == b'ok'\n"
            "assert seen['shell'] is False\n"
            "assert isinstance(seen['cmd'], list)\n"
        ),
        "security_tests": (
            "import subprocess, inspect\n"
            "text = inspect.getsource(list_files)\n"
            "assert 'shell=True' not in text\n"
            "seen={}\n"
            "def fake(cmd, shell=False):\n"
            "    seen['cmd']=cmd; seen['shell']=shell\n"
            "    return b''\n"
            "subprocess.check_output = fake\n"
            "list_files('x; id')\n"
            "assert seen.get('shell') is False\n"
            "assert isinstance(seen.get('cmd'), list)\n"
        ),
        "functional_tests": (
            "import subprocess\n"
            "def fake(cmd, shell=False):\n"
            "    return b'|'.join(x.encode() if isinstance(x,str) else x for x in cmd)\n"
            "subprocess.check_output = fake\n"
            "assert b'/data' in list_files('/data')\n"
        ),
        "forbidden_patterns": [r"shell\s*=\s*True"],
        "required_patterns": [],
    },
]


# Additional held-out vignettes (wording distinct from curated SFT seeds)
CURATED_EXECUTABLE += [
    {
        "id": "ho-py-redos-email",
        "language": "python",
        "cwe": "CWE-1333",
        "title": "Naive nested regex for email",
        "vulnerable_code": (
            "import re\n"
            "def is_email(s):\n"
            "    return re.match(r'^([a-zA-Z0-9]+\\.+)+[a-zA-Z0-9]+@', s) is not None\n"
        ),
        "secure_reference": (
            "import re\n"
            "EMAIL = re.compile(r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$')\n"
            "def is_email(s):\n"
            "    return EMAIL.fullmatch(s or '') is not None\n"
        ),
        "unit_tests": "assert is_email('a@b.co') is True\nassert is_email('bad') is False\n",
        "security_tests": (
            "import inspect\n"
            "text = inspect.getsource(is_email)\n"
            "assert 'fullmatch' in text or 'EMAIL' in text\n"
            "assert is_email('a@b.co') is True\n"
            "assert is_email('not-an-email') is False\n"
        ),
        "functional_tests": "assert is_email('user.name+tag@example.com') in (True, False)\n",
        "forbidden_patterns": [r"\(\[a-zA-Z0-9\]\+\\\.\\\+\)\+"],
        "required_patterns": [],
    },
    {
        "id": "ho-py-tmp-predictable",
        "language": "python",
        "cwe": "CWE-377",
        "title": "Predictable temp file name",
        "vulnerable_code": (
            "def write_temp(data):\n"
            "    path = '/tmp/app_upload.dat'\n"
            "    open(path, 'w').write(data)\n"
            "    return path\n"
        ),
        "secure_reference": (
            "import tempfile\n"
            "def write_temp(data):\n"
            "    f = tempfile.NamedTemporaryFile('w', delete=False)\n"
            "    try:\n"
            "        f.write(data)\n"
            "        return f.name\n"
            "    finally:\n"
            "        f.close()\n"
        ),
        "unit_tests": (
            "p = write_temp('hi')\n"
            "assert open(p).read() == 'hi'\n"
        ),
        "security_tests": (
            "import inspect\n"
            "text = inspect.getsource(write_temp)\n"
            "assert '/tmp/app_upload.dat' not in text\n"
            "assert 'NamedTemporaryFile' in text or 'mkstemp' in text\n"
        ),
        "functional_tests": "assert isinstance(write_temp('x'), str)\n",
        "forbidden_patterns": [r"/tmp/app_upload\.dat"],
        "required_patterns": [r"tempfile|mkstemp|NamedTemporaryFile"],
    },
    {
        "id": "ho-py-assert-auth",
        "language": "python",
        "cwe": "CWE-617",
        "title": "Auth gate via assert",
        "vulnerable_code": (
            "def require_admin(user):\n"
            "    assert user.get('role') == 'admin'\n"
            "    return True\n"
        ),
        "secure_reference": (
            "def require_admin(user):\n"
            "    if user.get('role') != 'admin':\n"
            "        raise PermissionError('admin only')\n"
            "    return True\n"
        ),
        "unit_tests": "assert require_admin({'role': 'admin'}) is True\n",
        "security_tests": (
            "import inspect\n"
            "text = inspect.getsource(require_admin)\n"
            "assert 'assert ' not in text\n"
            "raised=False\n"
            "try:\n"
            "    require_admin({'role': 'user'})\n"
            "except Exception:\n"
            "    raised=True\n"
            "assert raised\n"
        ),
        "functional_tests": "assert require_admin({'role': 'admin'}) is True\n",
        "forbidden_patterns": [r"\bassert\b"],
        "required_patterns": [r"raise|PermissionError|HTTPException"],
    },
    {
        "id": "ho-py-open-redirect",
        "language": "python",
        "cwe": "CWE-601",
        "title": "Open redirect via next param",
        "vulnerable_code": (
            "def next_url(next_param):\n"
            "    return next_param or '/'\n"
        ),
        "secure_reference": (
            "from urllib.parse import urlparse\n"
            "def next_url(next_param):\n"
            "    if not next_param:\n"
            "        return '/'\n"
            "    p = urlparse(next_param)\n"
            "    if p.scheme or p.netloc:\n"
            "        return '/'\n"
            "    if not next_param.startswith('/'):\n"
            "        return '/'\n"
            "    return next_param\n"
        ),
        "unit_tests": "assert next_url('/home') == '/home'\nassert next_url(None) == '/'\n",
        "security_tests": (
            "assert next_url('https://evil.example/phish') == '/'\n"
            "assert next_url('//evil.example') == '/'\n"
        ),
        "functional_tests": "assert next_url('/a/b') == '/a/b'\n",
        "forbidden_patterns": [],
        "required_patterns": [r"urlparse|startswith\(['\"]\/"],
    },
]

# Expand executable held-out well beyond the original ~16 vignettes
CURATED_EXECUTABLE += EXTRA_EXECUTABLE


def curated_rows() -> List[Dict[str, Any]]:
    rows = []
    for c in CURATED_EXECUTABLE:
        rows.append(
            {
                **c,
                "source": "curated_executable",
                "split": "heldout",
                "fingerprint": fingerprint(c["vulnerable_code"]),
                "has_unit": True,
                "has_security": True,
                "has_functional": True,
                "has_compile": True,
            }
        )
    return rows


def cvefixes_heldout(train_fps: Set[str], limit: int = 80) -> List[Dict[str, Any]]:
    rows = []
    reserve_ids: List[str] = []
    for p in load_jsonl(PROC / "cvefixes_pairs.jsonl"):
        vul = p.get("vulnerable_code") or ""
        sec = p.get("secure_code") or ""
        if len(vul.strip()) < 20 or len(sec.strip()) < 20:
            continue
        pid = str(p.get("id") or p.get("cve_id") or fingerprint(vul)[:12])
        # Deterministic 20% reserve for future retrain exclusion
        reserved = int(hashlib.sha1(pid.encode()).hexdigest(), 16) % 5 == 0
        if reserved:
            reserve_ids.append(pid)
        fp = fingerprint(vul)
        overlap = fp in train_fps or fingerprint(sec) in train_fps
        if overlap and not reserved:
            continue
        # Only keep truly disjoint OR (if none) skip overlapped entirely
        if overlap:
            continue
        rows.append(
            {
                "id": f"ho-cve-{pid}",
                "language": p.get("language") or "unknown",
                "cwe": p.get("cwe") or "",
                "title": p.get("cve_id") or p.get("id"),
                "vulnerable_code": vul,
                "secure_reference": sec,
                "source": "cvefixes_disjoint",
                "split": "heldout",
                "fingerprint": fp,
                "unit_tests": "",
                "security_tests": "",
                "functional_tests": "",
                "forbidden_patterns": [],
                "required_patterns": [],
                "has_unit": False,
                "has_security": False,
                "has_functional": False,
                "has_compile": (p.get("language") or "") in {"python", "javascript"},
            }
        )
    reserve_unique = sorted(set(reserve_ids))
    (PROC / "fix_eval_cve_reserve_ids.json").write_text(
        json.dumps(
            {
                "n": len(reserve_unique),
                "ids": reserve_unique,
                "policy": "sha1(id)%5==0 — exclude these from future sft_fix merges before retrain",
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    # Materialize the next-retrain holdout set (may overlap current sft_fix until rebuild excludes them)
    holdout_pairs = []
    for p in load_jsonl(PROC / "cvefixes_pairs.jsonl"):
        pid = str(p.get("id") or p.get("cve_id") or "")
        if pid in set(reserve_unique):
            holdout_pairs.append(p)
    (PROC / "cvefixes_holdout_next_retrain.jsonl").write_text(
        "\n".join(json.dumps(p, ensure_ascii=False) for p in holdout_pairs) + ("\n" if holdout_pairs else ""),
        encoding="utf-8",
    )
    (PROC / "cvefixes_holdout_next_retrain_meta.json").write_text(
        json.dumps(
            {
                "n": len(holdout_pairs),
                "policy": "20% sha1 reserve; exclude via ingest_cvefixes --exclude-holdout before next CodeT5 retrain",
                "ids_file": str(PROC / "fix_eval_cve_reserve_ids.json"),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    by_lang: Dict[str, List[Dict[str, Any]]] = {}
    for r in rows:
        by_lang.setdefault(r["language"], []).append(r)
    out: List[Dict[str, Any]] = []
    langs = sorted(by_lang.keys())
    i = 0
    while len(out) < limit and langs:
        lang = langs[i % len(langs)]
        bucket = by_lang[lang]
        if bucket:
            out.append(bucket.pop(0))
        else:
            langs.remove(lang)
            if not langs:
                break
            i = 0
            continue
        i += 1
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sft-fix", type=Path, default=PROC / "sft_fix.jsonl")
    ap.add_argument("--out", type=Path, default=PROC / "fix_eval_heldout.jsonl")
    ap.add_argument("--cve-limit", type=int, default=80)
    args = ap.parse_args()

    train_fps = train_fingerprints(args.sft_fix)
    curated = curated_rows()
    # Drop curated that accidentally collide with train fingerprints
    curated = [c for c in curated if c["fingerprint"] not in train_fps]
    cve = cvefixes_heldout(train_fps, limit=args.cve_limit)

    all_rows = curated + cve
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as f:
        for r in all_rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    meta = {
        "n_total": len(all_rows),
        "n_curated_executable": len(curated),
        "n_cvefixes_disjoint": len(cve),
        "train_fix_fingerprints": len(train_fps),
        "cve_reserve_ids_file": str(PROC / "fix_eval_cve_reserve_ids.json"),
        "note": (
            "Primary unbiased set = curated_executable (fingerprints not in sft_fix). "
            "CVEFixes next-retrain reserve lives in cvefixes_holdout_next_retrain.jsonl; "
            "rebuild_sft_exclude_holdout.py makes those fingerprints disjoint. "
            "Soft-match on sft_pairs is NOT a valid generalization claim."
        ),
        "out": str(args.out),
    }
    (PROC / "fix_eval_heldout_meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(json.dumps(meta, indent=2))


if __name__ == "__main__":
    main()
