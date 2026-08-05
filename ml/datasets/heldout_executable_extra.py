"""Extra curated executable held-out vignettes (imported by build_heldout_fix_eval).

Keep wording distinct from expand_sft / vibe templates to avoid near-duplicate soft leakage.
Target: push executable n well above the original 16.
"""

from __future__ import annotations

from typing import Any, Dict, List

EXTRA_EXECUTABLE: List[Dict[str, Any]] = [
    {
        "id": "ho-py-sqli-users-format",
        "language": "python",
        "cwe": "CWE-89",
        "title": "User lookup via str.format SQLi",
        "vulnerable_code": (
            "def find_user(db, name):\n"
            '    return db.execute("SELECT * FROM users WHERE name = \'{}\'".format(name))\n'
        ),
        "secure_reference": (
            "def find_user(db, name):\n"
            '    return db.execute("SELECT * FROM users WHERE name = ?", (name,))\n'
        ),
        "unit_tests": (
            "class DB:\n"
            "    def __init__(self):\n"
            "        self.a=[]\n"
            "    def execute(self,*a):\n"
            "        self.a.append(a); return {'ok':1}\n"
            "d=DB(); assert find_user(d,'alice')['ok']==1\n"
        ),
        "security_tests": (
            "class DB:\n"
            "    def __init__(self): self.a=[]\n"
            "    def execute(self,*a): self.a.append(a); return a\n"
            "d=DB(); find_user(d,\"x' OR '1'='1\");\n"
            "assert len(d.a[0])>=2 and \"OR\" not in str(d.a[0][0])\n"
        ),
        "functional_tests": (
            "class DB:\n"
            "    def execute(self,*a): return a\n"
            "assert find_user(DB(),'bob')[1]==('bob',) or find_user(DB(),'bob')[1]=='bob'\n"
        ),
        "forbidden_patterns": [r"\.format\(|%\s*\(|f[\"'].*SELECT"],
        "required_patterns": [r"\?|%s"],
    },
    {
        "id": "ho-py-cmdi-list-dir",
        "language": "python",
        "cwe": "CWE-78",
        "title": "listdir via shell=True",
        "vulnerable_code": (
            "import subprocess\n"
            "def list_dir(path):\n"
            "    return subprocess.check_output(f'ls {path}', shell=True)\n"
        ),
        "secure_reference": (
            "import subprocess\n"
            "def list_dir(path):\n"
            "    return subprocess.check_output(['ls', path])\n"
        ),
        "unit_tests": (
            "import subprocess as sp\n"
            "orig=sp.check_output\n"
            "sp.check_output=lambda *a,**k: b'ok'\n"
            "try:\n"
            "    assert list_dir('.')==b'ok'\n"
            "finally:\n"
            "    sp.check_output=orig\n"
        ),
        "security_tests": (
            "import inspect\n"
            "src=inspect.getsource(list_dir)\n"
            "assert 'shell=True' not in src\n"
            "assert 'shell' not in src or 'shell=False' in src\n"
        ),
        "functional_tests": (
            "import subprocess as sp\n"
            "calls=[]\n"
            "sp.check_output=lambda *a,**k: (calls.append((a,k)) or b'x')\n"
            "list_dir('/tmp')\n"
            "assert calls and isinstance(calls[0][0][0], (list,tuple))\n"
        ),
        "forbidden_patterns": [r"shell\s*=\s*True", r"os\.system"],
        "required_patterns": [r"subprocess|\[.ls"],
    },
    {
        "id": "ho-py-path-join-safe",
        "language": "python",
        "cwe": "CWE-22",
        "title": "Serve file under root without resolve check",
        "vulnerable_code": (
            "import os\n"
            "ROOT='/var/data'\n"
            "def read_asset(name):\n"
            "    return open(os.path.join(ROOT, name)).read()\n"
        ),
        "secure_reference": (
            "import os\n"
            "ROOT='/var/data'\n"
            "def read_asset(name):\n"
            "    path=os.path.realpath(os.path.join(ROOT, name))\n"
            "    if not path.startswith(os.path.realpath(ROOT)+os.sep):\n"
            "        raise ValueError('path escape')\n"
            "    return open(path).read()\n"
        ),
        "unit_tests": (
            "import os, tempfile\n"
            "td=tempfile.mkdtemp(); open(os.path.join(td,'a.txt'),'w').write('z')\n"
            "g=globals(); g['ROOT']=td\n"
            "assert read_asset('a.txt')=='z'\n"
        ),
        "security_tests": (
            "import os, tempfile, inspect\n"
            "assert 'realpath' in inspect.getsource(read_asset)\n"
            "td=tempfile.mkdtemp(); g=globals(); g['ROOT']=td\n"
            "raised=False\n"
            "try:\n"
            "    read_asset('../outside')\n"
            "except Exception:\n"
            "    raised=True\n"
            "assert raised\n"
        ),
        "functional_tests": (
            "import os, tempfile\n"
            "td=tempfile.mkdtemp(); open(os.path.join(td,'b.txt'),'w').write('y')\n"
            "globals()['ROOT']=td\n"
            "assert read_asset('b.txt')=='y'\n"
        ),
        "forbidden_patterns": [],
        "required_patterns": [r"realpath|commonpath|startswith"],
    },
    {
        "id": "ho-py-xss-escape-html",
        "language": "python",
        "cwe": "CWE-79",
        "title": "HTML comment render without escape",
        "vulnerable_code": (
            "def render_comment(user, text):\n"
            "    return f'<li><b>{user}</b>: {text}</li>'\n"
        ),
        "secure_reference": (
            "import html\n"
            "def render_comment(user, text):\n"
            "    return f'<li><b>{html.escape(user)}</b>: {html.escape(text)}</li>'\n"
        ),
        "unit_tests": "assert '<li>' in render_comment('a','hi')\n",
        "security_tests": (
            "out=render_comment('u','<script>x</script>')\n"
            "assert '<script>' not in out\n"
            "assert '&lt;script&gt;' in out or 'script' not in out.lower()\n"
        ),
        "functional_tests": "assert 'hi' in render_comment('bob','hi')\n",
        "forbidden_patterns": [],
        "required_patterns": [r"html\.escape|escape\("],
    },
    {
        "id": "ho-py-ssrf-fetch",
        "language": "python",
        "cwe": "CWE-918",
        "title": "Fetch any URL without allowlist",
        "vulnerable_code": (
            "import urllib.request\n"
            "def fetch(url):\n"
            "    return urllib.request.urlopen(url).read()\n"
        ),
        "secure_reference": (
            "from urllib.parse import urlparse\n"
            "import urllib.request\n"
            "ALLOW={'api.example.com'}\n"
            "def fetch(url):\n"
            "    host=urlparse(url).hostname or ''\n"
            "    if host not in ALLOW:\n"
            "        raise ValueError('host blocked')\n"
            "    return urllib.request.urlopen(url).read()\n"
        ),
        "unit_tests": (
            "class R: \n"
            "    def read(self): return b'ok'\n"
            "import urllib.request as u\n"
            "u.urlopen=lambda url: R()\n"
            "globals()['ALLOW']={'api.example.com'}\n"
            "assert fetch('https://api.example.com/x')==b'ok'\n"
        ),
        "security_tests": (
            "import inspect\n"
            "assert 'ALLOW' in inspect.getsource(fetch) or 'allow' in inspect.getsource(fetch).lower()\n"
            "raised=False\n"
            "try:\n"
            "    fetch('http://169.254.169.254/latest')\n"
            "except Exception:\n"
            "    raised=True\n"
            "assert raised\n"
        ),
        "functional_tests": (
            "class R:\n"
            "    def read(self): return b'z'\n"
            "import urllib.request as u\n"
            "u.urlopen=lambda url: R()\n"
            "globals()['ALLOW']={'api.example.com'}\n"
            "assert fetch('https://api.example.com/')==b'z'\n"
        ),
        "forbidden_patterns": [],
        "required_patterns": [r"ALLOW|allowlist|hostname"],
    },
    {
        "id": "ho-py-jwt-none-alg",
        "language": "python",
        "cwe": "CWE-347",
        "title": "Accept unsigned JWT alg none",
        "vulnerable_code": (
            "import json, base64\n"
            "def decode_jwt(token):\n"
            "    parts=token.split('.')\n"
            "    payload=parts[1]+'='*((4-len(parts[1])%4)%4)\n"
            "    return json.loads(base64.urlsafe_b64decode(payload))\n"
        ),
        "secure_reference": (
            "import json, base64, hmac, hashlib\n"
            "SECRET=b'secret'\n"
            "def decode_jwt(token):\n"
            "    h,p,s=token.split('.')\n"
            "    msg=f'{h}.{p}'.encode()\n"
            "    sig=base64.urlsafe_b64encode(hmac.new(SECRET, msg, hashlib.sha256).digest()).rstrip(b'=')\n"
            "    if s.encode()!=sig:\n"
            "        raise ValueError('bad sig')\n"
            "    payload=p+'='*((4-len(p)%4)%4)\n"
            "    return json.loads(base64.urlsafe_b64decode(payload))\n"
        ),
        "unit_tests": (
            "import json, base64, hmac, hashlib\n"
            "SECRET=b'secret'\n"
            "h=base64.urlsafe_b64encode(b'{\"alg\":\"HS256\"}').rstrip(b'=').decode()\n"
            "p=base64.urlsafe_b64encode(b'{\"sub\":\"1\"}').rstrip(b'=').decode()\n"
            "s=base64.urlsafe_b64encode(hmac.new(SECRET,f'{h}.{p}'.encode(),hashlib.sha256).digest()).rstrip(b'=').decode()\n"
            "globals()['SECRET']=SECRET\n"
            "assert decode_jwt(f'{h}.{p}.{s}')['sub']=='1'\n"
        ),
        "security_tests": (
            "import inspect\n"
            "src=inspect.getsource(decode_jwt)\n"
            "assert 'hmac' in src or 'verify' in src.lower() or 'sig' in src\n"
            "raised=False\n"
            "try:\n"
            "    decode_jwt('eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.')\n"
            "except Exception:\n"
            "    raised=True\n"
            "assert raised\n"
        ),
        "functional_tests": (
            "import json, base64, hmac, hashlib\n"
            "SECRET=b'secret'; globals()['SECRET']=SECRET\n"
            "h=base64.urlsafe_b64encode(b'{\"alg\":\"HS256\"}').rstrip(b'=').decode()\n"
            "p=base64.urlsafe_b64encode(b'{\"sub\":\"9\"}').rstrip(b'=').decode()\n"
            "s=base64.urlsafe_b64encode(hmac.new(SECRET,f'{h}.{p}'.encode(),hashlib.sha256).digest()).rstrip(b'=').decode()\n"
            "assert decode_jwt(f'{h}.{p}.{s}')['sub']=='9'\n"
        ),
        "forbidden_patterns": [],
        "required_patterns": [r"hmac|verify|signature|SECRET"],
    },
    {
        "id": "ho-py-pickle-load",
        "language": "python",
        "cwe": "CWE-502",
        "title": "Untrusted pickle.loads",
        "vulnerable_code": (
            "import pickle\n"
            "def load_cfg(blob):\n"
            "    return pickle.loads(blob)\n"
        ),
        "secure_reference": (
            "import json\n"
            "def load_cfg(blob):\n"
            "    if isinstance(blob, bytes):\n"
            "        blob=blob.decode()\n"
            "    return json.loads(blob)\n"
        ),
        "unit_tests": "assert load_cfg('{\"a\":1}')['a']==1 or load_cfg(b'{\"a\":1}')['a']==1\n",
        "security_tests": (
            "import inspect\n"
            "assert 'pickle' not in inspect.getsource(load_cfg)\n"
            "assert load_cfg('{\"k\":2}')['k']==2\n"
        ),
        "functional_tests": "assert isinstance(load_cfg('{\"ok\":true}'.replace('true','true')), dict) or load_cfg('{\"ok\":1}')['ok']==1\n",
        "forbidden_patterns": [r"pickle\.loads|yaml\.load\("],
        "required_patterns": [r"json\.loads"],
    },
    {
        "id": "ho-py-random-token",
        "language": "python",
        "cwe": "CWE-330",
        "title": "Session token via random.random",
        "vulnerable_code": (
            "import random\n"
            "def make_token():\n"
            "    return str(random.random())\n"
        ),
        "secure_reference": (
            "import secrets\n"
            "def make_token():\n"
            "    return secrets.token_urlsafe(32)\n"
        ),
        "unit_tests": "t=make_token(); assert isinstance(t,str) and len(t)>8\n",
        "security_tests": (
            "import inspect\n"
            "src=inspect.getsource(make_token)\n"
            "assert 'secrets' in src or 'token_urlsafe' in src or 'SystemRandom' in src\n"
            "assert 'random.random' not in src\n"
        ),
        "functional_tests": "assert make_token()!=make_token()\n",
        "forbidden_patterns": [r"random\.random|random\.randint"],
        "required_patterns": [r"secrets|token_urlsafe|token_hex"],
    },
    {
        "id": "ho-py-sql-like-concat",
        "language": "python",
        "cwe": "CWE-89",
        "title": "LIKE search via string concat",
        "vulnerable_code": (
            "def search(db, q):\n"
            "    return db.execute(\"SELECT * FROM items WHERE title LIKE '%\" + q + \"%'\")\n"
        ),
        "secure_reference": (
            "def search(db, q):\n"
            "    return db.execute(\"SELECT * FROM items WHERE title LIKE ?\", (f'%{q}%',))\n"
        ),
        "unit_tests": (
            "class DB:\n"
            "    def __init__(self): self.c=[]\n"
            "    def execute(self,*a): self.c.append(a); return []\n"
            "d=DB(); search(d,'x'); assert d.c\n"
        ),
        "security_tests": (
            "class DB:\n"
            "    def __init__(self): self.c=[]\n"
            "    def execute(self,*a): self.c.append(a); return []\n"
            "d=DB(); search(d,\"%' OR '1'='1\");\n"
            "assert len(d.c[0])>=2\n"
        ),
        "functional_tests": (
            "class DB:\n"
            "    def execute(self,*a): return a\n"
            "r=search(DB(),'ab')\n"
            "assert isinstance(r[1], tuple)\n"
        ),
        "forbidden_patterns": [r"\+\s*q\s*\+|f[\"'].*LIKE"],
        "required_patterns": [r"\?"],
    },
    {
        "id": "ho-py-debug-flask-false",
        "language": "python",
        "cwe": "CWE-489",
        "title": "Flask debug True in production entry",
        "vulnerable_code": (
            "def run_app(app):\n"
            "    app.run(debug=True, host='0.0.0.0')\n"
        ),
        "secure_reference": (
            "def run_app(app):\n"
            "    app.run(debug=False, host='127.0.0.1')\n"
        ),
        "unit_tests": (
            "class A:\n"
            "    def run(self,**k): self.k=k\n"
            "a=A(); run_app(a); assert 'debug' in a.k\n"
        ),
        "security_tests": (
            "class A:\n"
            "    def run(self,**k): self.k=k\n"
            "a=A(); run_app(a)\n"
            "assert a.k.get('debug') is False\n"
        ),
        "functional_tests": (
            "class A:\n"
            "    def run(self,**k): self.k=k\n"
            "a=A(); run_app(a); assert 'host' in a.k\n"
        ),
        "forbidden_patterns": [r"debug\s*=\s*True"],
        "required_patterns": [r"debug\s*=\s*False"],
    },
    {
        "id": "ho-py-eval-math",
        "language": "python",
        "cwe": "CWE-95",
        "title": "eval user expression",
        "vulnerable_code": (
            "def calc(expr):\n"
            "    return eval(expr)\n"
        ),
        "secure_reference": (
            "import ast\n"
            "def calc(expr):\n"
            "    tree=ast.parse(expr, mode='eval')\n"
            "    for n in ast.walk(tree):\n"
            "        if not isinstance(n, (ast.Expression, ast.BinOp, ast.UnaryOp, ast.Constant, ast.Num,\n"
            "                                ast.Add, ast.Sub, ast.Mult, ast.Div, ast.USub, ast.UAdd, ast.Pow, ast.Mod)):\n"
            "            if type(n).__name__ not in {'Load','Expression'}:\n"
            "                raise ValueError('bad')\n"
            "    return eval(compile(tree, '<calc>', 'eval'), {'__builtins__': {}})\n"
        ),
        "unit_tests": "assert calc('1+2')==3\n",
        "security_tests": (
            "raised=False\n"
            "try:\n"
            "    calc(\"__import__('os').system('id')\")\n"
            "except Exception:\n"
            "    raised=True\n"
            "assert raised\n"
        ),
        "functional_tests": "assert calc('10-3')==7\n",
        "forbidden_patterns": [r"(?<!compile\()eval\("],
        "required_patterns": [r"ast\.parse|literal_eval"],
    },
    {
        "id": "ho-py-md5-password",
        "language": "python",
        "cwe": "CWE-328",
        "title": "Password hash with MD5",
        "vulnerable_code": (
            "import hashlib\n"
            "def hash_pw(pw):\n"
            "    return hashlib.md5(pw.encode()).hexdigest()\n"
        ),
        "secure_reference": (
            "import hashlib\n"
            "def hash_pw(pw):\n"
            "    return hashlib.sha256(pw.encode()).hexdigest()\n"
        ),
        "unit_tests": "h=hash_pw('x'); assert isinstance(h,str) and len(h)==64\n",
        "security_tests": (
            "import inspect\n"
            "src=inspect.getsource(hash_pw)\n"
            "assert 'md5' not in src.lower()\n"
            "assert 'sha256' in src or 'pbkdf2' in src or 'bcrypt' in src\n"
        ),
        "functional_tests": "assert hash_pw('a')!=hash_pw('b')\n",
        "forbidden_patterns": [r"md5\("],
        "required_patterns": [r"sha256|pbkdf2|bcrypt|scrypt|argon"],
    },
    {
        "id": "ho-py-yaml-unsafe",
        "language": "python",
        "cwe": "CWE-502",
        "title": "Prefer json over unsafe yaml.load",
        "vulnerable_code": (
            "def load_cfg(text):\n"
            "    import yaml\n"
            "    return yaml.load(text)\n"
        ),
        "secure_reference": (
            "import json\n"
            "def load_cfg(text):\n"
            "    return json.loads(text)\n"
        ),
        "unit_tests": "assert load_cfg('{\"a\": 1}')['a']==1\n",
        "security_tests": (
            "import inspect\n"
            "src=inspect.getsource(load_cfg)\n"
            "assert 'yaml.load' not in src\n"
            "assert 'json.loads' in src\n"
        ),
        "functional_tests": "assert load_cfg('{\"ok\": 1}')['ok']==1\n",
        "forbidden_patterns": [r"yaml\.load\("],
        "required_patterns": [r"json\.loads"],
    },
    {
        "id": "ho-py-cors-star",
        "language": "python",
        "cwe": "CWE-942",
        "title": "CORS Allow-Origin star with credentials pattern",
        "vulnerable_code": (
            "def cors_headers(origin):\n"
            "    return {'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Credentials': 'true'}\n"
        ),
        "secure_reference": (
            "ALLOW={'https://app.example.com'}\n"
            "def cors_headers(origin):\n"
            "    o=origin if origin in ALLOW else 'https://app.example.com'\n"
            "    return {'Access-Control-Allow-Origin': o, 'Access-Control-Allow-Credentials': 'true'}\n"
        ),
        "unit_tests": (
            "globals()['ALLOW']={'https://app.example.com'}\n"
            "h=cors_headers('https://app.example.com')\n"
            "assert 'Access-Control-Allow-Origin' in h\n"
        ),
        "security_tests": (
            "globals()['ALLOW']={'https://app.example.com'}\n"
            "h=cors_headers('https://evil.example')\n"
            "assert h['Access-Control-Allow-Origin']!='*'\n"
            "assert h['Access-Control-Allow-Origin']=='https://app.example.com'\n"
        ),
        "functional_tests": (
            "globals()['ALLOW']={'https://app.example.com'}\n"
            "assert cors_headers('https://app.example.com')['Access-Control-Allow-Origin']=='https://app.example.com'\n"
        ),
        "forbidden_patterns": [r"Allow-Origin['\"]:\s*['\"]\*['\"]"],
        "required_patterns": [r"ALLOW|allowlist|origin"],
    },
    {
        "id": "ho-py-log-injection",
        "language": "python",
        "cwe": "CWE-117",
        "title": "Log raw user input with newlines",
        "vulnerable_code": (
            "def audit(user, msg):\n"
            "    return f'user={user} msg={msg}'\n"
        ),
        "secure_reference": (
            "def audit(user, msg):\n"
            "    u=str(user).replace('\\n',' ').replace('\\r',' ')\n"
            "    m=str(msg).replace('\\n',' ').replace('\\r',' ')\n"
            "    return f'user={u} msg={m}'\n"
        ),
        "unit_tests": "assert 'user=' in audit('a','b')\n",
        "security_tests": (
            "out=audit('bob','hi\\nADMIN forged')\n"
            "assert '\\n' not in out\n"
        ),
        "functional_tests": "assert 'hello' in audit('u','hello')\n",
        "forbidden_patterns": [],
        "required_patterns": [r"replace\(|re\.sub|sanitize"],
    },
    {
        "id": "ho-py-int-overflow-gate",
        "language": "python",
        "cwe": "CWE-190",
        "title": "Quantity without upper bound",
        "vulnerable_code": (
            "def line_total(price, qty):\n"
            "    return price * int(qty)\n"
        ),
        "secure_reference": (
            "def line_total(price, qty):\n"
            "    q=int(qty)\n"
            "    if q < 0 or q > 1000:\n"
            "        raise ValueError('qty')\n"
            "    return price * q\n"
        ),
        "unit_tests": "assert line_total(2,3)==6\n",
        "security_tests": (
            "raised=False\n"
            "try:\n"
            "    line_total(1, 10**9)\n"
            "except Exception:\n"
            "    raised=True\n"
            "assert raised\n"
        ),
        "functional_tests": "assert line_total(5,2)==10\n",
        "forbidden_patterns": [],
        "required_patterns": [r"1000|max|bound|raise"],
    },
    {
        "id": "ho-py-http-verify-ssl",
        "language": "python",
        "cwe": "CWE-295",
        "title": "TLS verify flag must stay True",
        "vulnerable_code": (
            "def tls_opts():\n"
            "    return {'verify': False}\n"
        ),
        "secure_reference": (
            "def tls_opts():\n"
            "    return {'verify': True}\n"
        ),
        "unit_tests": "assert isinstance(tls_opts(), dict) and 'verify' in tls_opts()\n",
        "security_tests": "assert tls_opts().get('verify') is True\n",
        "functional_tests": "assert set(tls_opts().keys())=={'verify'}\n",
        "forbidden_patterns": [r"verify['\"]?\s*:\s*False|verify\s*=\s*False"],
        "required_patterns": [r"True"],
    },
    {
        "id": "ho-py-mass-assign",
        "language": "python",
        "cwe": "CWE-915",
        "title": "Mass assign role from body",
        "vulnerable_code": (
            "def update_user(user, body):\n"
            "    user.update(body)\n"
            "    return user\n"
        ),
        "secure_reference": (
            "ALLOWED={'name','email'}\n"
            "def update_user(user, body):\n"
            "    for k,v in body.items():\n"
            "        if k in ALLOWED:\n"
            "            user[k]=v\n"
            "    return user\n"
        ),
        "unit_tests": (
            "globals()['ALLOWED']={'name','email'}\n"
            "u={'name':'a','role':'user'}\n"
            "assert update_user(u,{'name':'b'})['name']=='b'\n"
        ),
        "security_tests": (
            "globals()['ALLOWED']={'name','email'}\n"
            "u={'name':'a','role':'user'}\n"
            "update_user(u,{'role':'admin'})\n"
            "assert u['role']=='user'\n"
        ),
        "functional_tests": (
            "globals()['ALLOWED']={'name','email'}\n"
            "u={'name':'a'}\n"
            "assert update_user(u,{'email':'x@y.z'})['email']=='x@y.z'\n"
        ),
        "forbidden_patterns": [r"\.update\(\s*body\s*\)"],
        "required_patterns": [r"ALLOWED|allowlist|whitelist"],
    },
    {
        "id": "ho-py-timing-compare",
        "language": "python",
        "cwe": "CWE-208",
        "title": "API key compare with ==",
        "vulnerable_code": (
            "def check_key(got, expected):\n"
            "    return got == expected\n"
        ),
        "secure_reference": (
            "import hmac\n"
            "def check_key(got, expected):\n"
            "    return hmac.compare_digest(str(got), str(expected))\n"
        ),
        "unit_tests": "assert check_key('abc','abc') is True\nassert check_key('a','b') is False\n",
        "security_tests": (
            "import inspect\n"
            "assert 'compare_digest' in inspect.getsource(check_key)\n"
        ),
        "functional_tests": "assert check_key('zz','zz')\n",
        "forbidden_patterns": [],
        "required_patterns": [r"compare_digest"],
    },
    {
        "id": "ho-py-xxe-etree",
        "language": "python",
        "cwe": "CWE-611",
        "title": "Reject DOCTYPE in XML payload",
        "vulnerable_code": (
            "def accept_xml(data):\n"
            "    return True\n"
        ),
        "secure_reference": (
            "def accept_xml(data):\n"
            "    text=str(data or '')\n"
            "    if '<!DOCTYPE' in text or '<!ENTITY' in text:\n"
            "        raise ValueError('xxe')\n"
            "    return True\n"
        ),
        "unit_tests": "assert accept_xml('<root/>') is True\n",
        "security_tests": (
            "raised=False\n"
            "try:\n"
            "    accept_xml('<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>')\n"
            "except Exception:\n"
            "    raised=True\n"
            "assert raised\n"
        ),
        "functional_tests": "assert accept_xml('<a>1</a>') is True\n",
        "forbidden_patterns": [],
        "required_patterns": [r"DOCTYPE|ENTITY|raise"],
    },
    {
        "id": "ho-py-ip-bind",
        "language": "python",
        "cwe": "CWE-605",
        "title": "Bind server on 0.0.0.0 unnecessarily",
        "vulnerable_code": (
            "import socket\n"
            "def listen(port):\n"
            "    s=socket.socket()\n"
            "    s.bind(('0.0.0.0', port))\n"
            "    return s\n"
        ),
        "secure_reference": (
            "import socket\n"
            "def listen(port):\n"
            "    s=socket.socket()\n"
            "    s.bind(('127.0.0.1', port))\n"
            "    return s\n"
        ),
        "unit_tests": (
            "import socket\n"
            "bound=[]\n"
            "class S:\n"
            "    def bind(self, addr): bound.append(addr)\n"
            "socket.socket=lambda *a,**k: S()\n"
            "listen(9); assert bound\n"
        ),
        "security_tests": (
            "import socket\n"
            "bound=[]\n"
            "class S:\n"
            "    def bind(self, addr): bound.append(addr)\n"
            "socket.socket=lambda *a,**k: S()\n"
            "listen(9)\n"
            "assert bound[0][0]=='127.0.0.1'\n"
        ),
        "functional_tests": (
            "import socket\n"
            "bound=[]\n"
            "class S:\n"
            "    def bind(self, addr): bound.append(addr)\n"
            "socket.socket=lambda *a,**k: S()\n"
            "listen(42); assert bound[0][1]==42\n"
        ),
        "forbidden_patterns": [r"0\.0\.0\.0"],
        "required_patterns": [r"127\.0\.0\.1"],
    },
    {
        "id": "ho-py-redirect-relative",
        "language": "python",
        "cwe": "CWE-601",
        "title": "Accept protocol-relative redirect",
        "vulnerable_code": (
            "def safe_next(n):\n"
            "    return n if n else '/'\n"
        ),
        "secure_reference": (
            "def safe_next(n):\n"
            "    if not n or not n.startswith('/') or n.startswith('//'):\n"
            "        return '/'\n"
            "    return n\n"
        ),
        "unit_tests": "assert safe_next('/x')=='/x'\n",
        "security_tests": "assert safe_next('//evil.test')=='/'\nassert safe_next('https://x')=='/' or safe_next('https://x')!='https://x'\n",
        "functional_tests": "assert safe_next('/a/b')=='/a/b'\n",
        "forbidden_patterns": [],
        "required_patterns": [r"startswith"],
    },
    {
        "id": "ho-py-regex-timeout",
        "language": "python",
        "cwe": "CWE-1333",
        "title": "Catastrophic backtracking regex",
        "vulnerable_code": (
            "import re\n"
            "def match_tag(s):\n"
            "    return re.match(r'^(a+)+$', s) is not None\n"
        ),
        "secure_reference": (
            "import re\n"
            "TAG=re.compile(r'^a+$')\n"
            "def match_tag(s):\n"
            "    return TAG.fullmatch(s or '') is not None\n"
        ),
        "unit_tests": "assert match_tag('aaa') is True\nassert match_tag('ab') is False\n",
        "security_tests": (
            "import inspect\n"
            "src=inspect.getsource(match_tag)\n"
            "assert '(a+)+' not in src\n"
        ),
        "functional_tests": "assert match_tag('a') is True\n",
        "forbidden_patterns": [r"\(a\+\)\+"],
        "required_patterns": [r"fullmatch|simple"],
    },
    {
        "id": "ho-py-secret-in-url",
        "language": "python",
        "cwe": "CWE-598",
        "title": "Pass API key in query string",
        "vulnerable_code": (
            "def build_url(base, key):\n"
            "    return f'{base}?api_key={key}'\n"
        ),
        "secure_reference": (
            "def build_url(base, key):\n"
            "    # key must be sent via header by caller; URL has no secret\n"
            "    return base.rstrip('?')\n"
        ),
        "unit_tests": "assert isinstance(build_url('https://api','k'), str)\n",
        "security_tests": (
            "u=build_url('https://api.example/v1','SUPERSECRET')\n"
            "assert 'SUPERSECRET' not in u\n"
            "assert 'api_key=' not in u\n"
        ),
        "functional_tests": "assert build_url('https://api.example/v1','k').startswith('https://')\n",
        "forbidden_patterns": [r"api_key=\{|api_key="],
        "required_patterns": [],
    },
]
