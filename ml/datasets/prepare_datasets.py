"""
Build real fine-tune datasets for SecureCode Copilot.

Outputs:
  processed/detector/train.jsonl|valid.jsonl|test.jsonl   (classification)
  processed/sft.jsonl                                      (explain + fix)
  processed/hard_negatives.jsonl
  processed/meta.json

Sources:
  - curated multilingual vuln/safe pairs (repo sample + built-in expansions)
  - hard negatives (looks risky but safe)  → giảm FP
  - optional HuggingFace Devign / CodeXGLUE defect detection (C)

Usage:
  python ml/datasets/prepare_datasets.py --out ml/datasets/processed --max-devign 4000
"""

from __future__ import annotations

import argparse
import json
import random
import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]

from vibe_patterns import VIBE_CURATED, VIBE_HARD_NEGATIVES  # noqa: E402
from lang_extra import LANG_CURATED  # noqa: E402


# ---------------------------------------------------------------------------
# Curated multi-lang pairs (vuln / secure) — seed for detector + SFT
# ---------------------------------------------------------------------------
CURATED: List[Dict[str, Any]] = [
    {
        "id": "py-sqli-fstring",
        "language": "python",
        "cwe": "CWE-89",
        "severity": "critical",
        "vulnerable_code": 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
        "secure_code": 'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
        "explanation": "f-string SQL cho phép attacker chèn mệnh đề OR 1=1 / UNION.",
    },
    {
        "id": "py-sqli-concat",
        "language": "python",
        "cwe": "CWE-89",
        "severity": "critical",
        "vulnerable_code": 'query = "SELECT * FROM t WHERE name='" + name + "'"; cursor.execute(query)',
        "secure_code": 'cursor.execute("SELECT * FROM t WHERE name = %s", (name,))',
        "explanation": "Nối chuỗi SQL là SQL Injection cổ điển.",
    },
    {
        "id": "py-cmdi-system",
        "language": "python",
        "cwe": "CWE-78",
        "severity": "critical",
        "vulnerable_code": 'os.system("ping " + host)',
        "secure_code": 'subprocess.run(["ping", "-c", "1", host], check=True)',
        "explanation": "os.system gọi shell; host có thể chứa ; rm -rf.",
    },
    {
        "id": "py-cmdi-shelltrue",
        "language": "python",
        "cwe": "CWE-78",
        "severity": "critical",
        "vulnerable_code": 'subprocess.call("ls " + path, shell=True)',
        "secure_code": 'subprocess.call(["ls", path])',
        "explanation": "shell=True + input ngoài = command injection.",
    },
    {
        "id": "py-pickle",
        "language": "python",
        "cwe": "CWE-502",
        "severity": "critical",
        "vulnerable_code": "obj = pickle.loads(user_blob)",
        "secure_code": "obj = json.loads(user_blob)",
        "explanation": "pickle có thể thực thi mã khi loads.",
    },
    {
        "id": "py-eval",
        "language": "python",
        "cwe": "CWE-95",
        "severity": "critical",
        "vulnerable_code": "return eval(user_expr)",
        "secure_code": "return ast.literal_eval(user_expr)",
        "explanation": "eval chạy arbitrary Python.",
    },
    {
        "id": "py-path",
        "language": "python",
        "cwe": "CWE-22",
        "severity": "high",
        "vulnerable_code": 'open("/data/" + filename).read()',
        "secure_code": 'p = Path("/data").joinpath(filename).resolve()\nassert str(p).startswith("/data")\nopen(p).read()',
        "explanation": "filename=../etc/passwd → path traversal.",
    },
    {
        "id": "py-hardcode",
        "language": "python",
        "cwe": "CWE-798",
        "severity": "high",
        "vulnerable_code": 'API_KEY = "sk-prod-abc123xyz999"',
        "secure_code": 'API_KEY = os.environ["API_KEY"]',
        "explanation": "Secret hard-code dễ lộ trên git.",
    },
    {
        "id": "js-sqli",
        "language": "javascript",
        "cwe": "CWE-89",
        "severity": "critical",
        "vulnerable_code": "db.query(`SELECT * FROM users WHERE id = ${id}`)",
        "secure_code": 'db.query("SELECT * FROM users WHERE id = $1", [id])',
        "explanation": "Template SQL injectable.",
    },
    {
        "id": "js-xss",
        "language": "javascript",
        "cwe": "CWE-79",
        "severity": "high",
        "vulnerable_code": "el.innerHTML = userInput;",
        "secure_code": "el.textContent = userInput;",
        "explanation": "innerHTML parse HTML → XSS.",
    },
    {
        "id": "js-eval",
        "language": "javascript",
        "cwe": "CWE-95",
        "severity": "critical",
        "vulnerable_code": "return eval(code);",
        "secure_code": "return JSON.parse(code);",
        "explanation": "eval chạy JS tùy ý.",
    },
    {
        "id": "js-cmdi",
        "language": "javascript",
        "cwe": "CWE-78",
        "severity": "critical",
        "vulnerable_code": 'exec("ls " + dir);',
        "secure_code": 'execFile("ls", [dir]);',
        "explanation": "exec với shell string = command injection.",
    },
    {
        "id": "js-path",
        "language": "javascript",
        "cwe": "CWE-22",
        "severity": "high",
        "vulnerable_code": "fs.readFileSync(path.join(base, req.query.file))",
        "secure_code": 'const p = path.resolve(base, req.query.file);\nif (!p.startsWith(base)) throw new Error("deny");\nfs.readFileSync(p);',
        "explanation": "Path không chuẩn hoá → traversal.",
    },
    {
        "id": "java-sqli",
        "language": "java",
        "cwe": "CWE-89",
        "severity": "critical",
        "vulnerable_code": 'st.executeQuery("SELECT * FROM users WHERE id=" + userId);',
        "secure_code": 'PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id=?");\nps.setString(1, userId);\nps.executeQuery();',
        "explanation": "Statement nối chuỗi = SQLi.",
    },
    {
        "id": "java-cmdi",
        "language": "java",
        "cwe": "CWE-78",
        "severity": "critical",
        "vulnerable_code": 'Runtime.getRuntime().exec("ping " + host);',
        "secure_code": 'new ProcessBuilder("ping", "-c", "1", host).start();',
        "explanation": "Runtime.exec nối chuỗi nguy hiểm.",
    },
    {
        "id": "java-xxe",
        "language": "java",
        "cwe": "CWE-611",
        "severity": "high",
        "vulnerable_code": "DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(in);",
        "secure_code": 'DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\ndbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\ndbf.newDocumentBuilder().parse(in);',
        "explanation": "Parser mặc định có thể dính XXE.",
    },
    {
        "id": "java-deser",
        "language": "java",
        "cwe": "CWE-502",
        "severity": "critical",
        "vulnerable_code": "Object o = new ObjectInputStream(in).readObject();",
        "secure_code": "MyDto dto = new ObjectMapper().readValue(in, MyDto.class);",
        "explanation": "Java deserialization gadget → RCE.",
    },
    {
        "id": "c-strcpy",
        "language": "c",
        "cwe": "CWE-120",
        "severity": "critical",
        "vulnerable_code": "strcpy(buf, src);",
        "secure_code": 'snprintf(buf, sizeof(buf), "%s", src);',
        "explanation": "strcpy không giới hạn độ dài.",
    },
    {
        "id": "c-fmt",
        "language": "c",
        "cwe": "CWE-134",
        "severity": "high",
        "vulnerable_code": "printf(user);",
        "secure_code": 'printf("%s", user);',
        "explanation": "Format string do user kiểm soát.",
    },
    {
        "id": "c-system",
        "language": "c",
        "cwe": "CWE-78",
        "severity": "critical",
        "vulnerable_code": "system(cmd);",
        "secure_code": 'char *argv[] = {"/bin/ls", "-la", NULL};\nexecve(argv[0], argv, environ);',
        "explanation": "system() gọi shell.",
    },
]


# Hard negatives: LOOK like vulns to naive rules/models but are safe.
HARD_NEGATIVES: List[Dict[str, Any]] = [
    {
        "id": "hn-py-param-sql",
        "language": "python",
        "cwe": "CWE-89",
        "code": 'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
        "why_safe": "Parameterized query — không phải SQLi.",
    },
    {
        "id": "hn-py-subprocess-list",
        "language": "python",
        "cwe": "CWE-78",
        "code": 'subprocess.run(["ping", "-c", "1", host], check=True)',
        "why_safe": "Không shell=True; argv tách.",
    },
    {
        "id": "hn-py-literal-eval",
        "language": "python",
        "cwe": "CWE-95",
        "code": "value = ast.literal_eval(user_input)",
        "why_safe": "literal_eval chỉ parse literal.",
    },
    {
        "id": "hn-py-json",
        "language": "python",
        "cwe": "CWE-502",
        "code": "data = json.loads(payload)",
        "why_safe": "JSON không thực thi gadget như pickle.",
    },
    {
        "id": "hn-py-path-check",
        "language": "python",
        "cwe": "CWE-22",
        "code": 'p = Path(BASE).joinpath(name).resolve()\nif not str(p).startswith(str(Path(BASE).resolve())): raise ValueError("deny")\nopen(p)',
        "why_safe": "Có resolve + prefix check.",
    },
    {
        "id": "hn-js-textcontent",
        "language": "javascript",
        "cwe": "CWE-79",
        "code": "el.textContent = userInput;",
        "why_safe": "textContent không parse HTML.",
    },
    {
        "id": "hn-js-param-sql",
        "language": "javascript",
        "cwe": "CWE-89",
        "code": 'await db.query("SELECT * FROM users WHERE id = $1", [userId])',
        "why_safe": "Bind parameter.",
    },
    {
        "id": "hn-js-execfile",
        "language": "javascript",
        "cwe": "CWE-78",
        "code": 'execFile("ls", ["-la", safePath]);',
        "why_safe": "execFile không qua shell.",
    },
    {
        "id": "hn-js-jsonparse",
        "language": "javascript",
        "cwe": "CWE-95",
        "code": "const data = JSON.parse(userInput);",
        "why_safe": "Không eval.",
    },
    {
        "id": "hn-java-prepared",
        "language": "java",
        "cwe": "CWE-89",
        "code": 'PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id=?");\nps.setInt(1, id);',
        "why_safe": "PreparedStatement an toàn.",
    },
    {
        "id": "hn-java-processbuilder",
        "language": "java",
        "cwe": "CWE-78",
        "code": 'new ProcessBuilder("ping", "-c", "1", host).start();',
        "why_safe": "Args list cố định, không nối shell string.",
    },
    {
        "id": "hn-java-xxe-safe",
        "language": "java",
        "cwe": "CWE-611",
        "code": 'DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\ndbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\ndbf.setExpandEntityReferences(false);',
        "why_safe": "XXE features đã tắt.",
    },
    {
        "id": "hn-c-snprintf",
        "language": "c",
        "cwe": "CWE-120",
        "code": 'snprintf(dst, sizeof(dst), "%s", src);',
        "why_safe": "Có bound size.",
    },
    {
        "id": "hn-c-printf-s",
        "language": "c",
        "cwe": "CWE-134",
        "code": 'printf("%s", user);',
        "why_safe": "Format cố định.",
    },
    {
        "id": "hn-c-no-system",
        "language": "c",
        "cwe": "CWE-78",
        "code": 'char *argv[] = {"/bin/ls", "-la", NULL}; execve(argv[0], argv, environ);',
        "why_safe": "Không gọi system().",
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
]


TEMPLATES_EXPAND = {
    "python": [
        (
            "CWE-89",
            'db.execute(f"UPDATE accounts SET bal={amt} WHERE id={uid}")',
            'db.execute("UPDATE accounts SET bal=? WHERE id=?", (amt, uid))',
            "f-string UPDATE injectable.",
        ),
        (
            "CWE-78",
            'os.popen("cat " + fname).read()',
            'subprocess.check_output(["cat", fname], text=True)',
            "os.popen dùng shell.",
        ),
    ],
    "javascript": [
        (
            "CWE-89",
            "connection.query('SELECT * FROM t WHERE id=' + req.params.id)",
            "connection.query('SELECT * FROM t WHERE id=?', [req.params.id])",
            "Concat SQL.",
        ),
        (
            "CWE-79",
            "document.write(location.hash)",
            "document.write(DOMPurify.sanitize(location.hash))",
            "document.write XSS.",
        ),
    ],
    "java": [
        (
            "CWE-89",
            'String sql = "DELETE FROM users WHERE name='" + name + "'"; stmt.execute(sql);',
            'PreparedStatement ps = c.prepareStatement("DELETE FROM users WHERE name=?"); ps.setString(1, name);',
            "Concat DELETE SQL.",
        ),
    ],
    "c": [
        (
            "CWE-120",
            "gets(buf);",
            "fgets(buf, sizeof(buf), stdin);",
            "gets không bound.",
        ),
        (
            "CWE-120",
            "sprintf(out, \"%s\", src);",
            "snprintf(out, sizeof(out), \"%s\", src);",
            "sprintf không bound output.",
        ),
    ],
}


def write_jsonl(path: Path, rows: Iterable[Dict]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
            n += 1
    return n


def load_sample_jsonl() -> List[Dict[str, Any]]:
    sample = HERE / "sample" / "securecode_sft.jsonl"
    if not sample.exists():
        return []
    rows = []
    for line in sample.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def expand_curated(seed: int = 42) -> List[Dict[str, Any]]:
    random.seed(seed)
    rows = list(CURATED) + list(VIBE_CURATED) + list(LANG_CURATED) + load_sample_jsonl()
    # de-dup by id if present
    seen = set()
    uniq = []
    for r in rows:
        key = r.get("id") or (r.get("vulnerable_code"), r.get("language"))
        if key in seen:
            continue
        seen.add(key)
        uniq.append(r)

    extra = []
    idx = 0
    for lang, items in TEMPLATES_EXPAND.items():
        for cwe, vuln, secure, expl in items:
            idx += 1
            extra.append(
                {
                    "id": f"exp-{lang}-{idx}",
                    "language": lang,
                    "cwe": cwe,
                    "severity": "high",
                    "vulnerable_code": vuln,
                    "secure_code": secure,
                    "explanation": expl,
                }
            )
    return uniq + extra


def all_hard_negatives() -> List[Dict[str, Any]]:
    return list(HARD_NEGATIVES) + list(VIBE_HARD_NEGATIVES)


def try_load_cvefixes_langs(max_per_lang: int = 200, langs: Optional[List[str]] = None) -> List[Dict]:
    """Load Younis2003/secure_dataset_cvefixes filtered for php/cpp (+ csharp if present)."""
    if max_per_lang <= 0:
        return []
    langs = langs or ["php", "cpp", "c++", "csharp", "c#"]
    try:
        from datasets import load_dataset
    except ImportError:
        print("[warn] datasets not installed — skip CVEFixes HF")
        return []

    want = {x.lower().replace("c++", "cpp").replace("c#", "csharp") for x in langs}
    out: List[Dict] = []
    counts: Dict[str, int] = {}
    for name in (
        "hitoshura25/cvefixes",
        "Younis2003/secure_dataset_cvefixes",
        "Younis2003/codellama_security_cvefixes",
    ):
        try:
            print(f"[info] trying CVEFixes-derived HF: {name}")
            ds = load_dataset(name, trust_remote_code=True)
            split = ds["train"] if "train" in ds else ds[list(ds.keys())[0]]
            for i, ex in enumerate(split):
                lang_raw = str(ex.get("language") or ex.get("lang") or "").lower()
                lang = lang_raw.replace("c++", "cpp").replace("c#", "csharp")
                if lang not in want and lang_raw not in want:
                    # try infer from fields
                    blob = json.dumps(ex)[:500].lower()
                    if "php" in want and "php" in blob:
                        lang = "php"
                    elif "cpp" in want and ("c++" in blob or "cpp" in blob):
                        lang = "cpp"
                    else:
                        continue
                if counts.get(lang, 0) >= max_per_lang:
                    continue
                vuln = (
                    ex.get("vulnerable_code")
                    or ex.get("before")
                    or ex.get("func_before")
                    or ex.get("code_before")
                    or ex.get("input")
                )
                secure = (
                    ex.get("secure_code")
                    or ex.get("fixed_code")
                    or ex.get("after")
                    or ex.get("func_after")
                    or ex.get("code_after")
                    or ex.get("output")
                )
                if not vuln:
                    continue
                cwe = str(ex.get("cwe") or ex.get("CWE") or "CWE-000")
                if not str(cwe).startswith("CWE"):
                    cwe = f"CWE-{cwe}" if str(cwe).isdigit() else "CWE-000"
                out.append(
                    {
                        "id": f"cvefix-{lang}-{i}",
                        "language": "cpp" if lang in ("c++", "cpp") else ("csharp" if lang in ("c#", "csharp") else lang),
                        "cwe": cwe,
                        "code": str(vuln)[:4000],
                        "label": 1,
                        "source": f"hf:{name}",
                    }
                )
                if secure:
                    out.append(
                        {
                            "id": f"cvefix-{lang}-{i}-safe",
                            "language": out[-1]["language"],
                            "cwe": cwe,
                            "code": str(secure)[:4000],
                            "label": 0,
                            "source": f"hf:{name}:secure",
                        }
                    )
                counts[lang] = counts.get(lang, 0) + 1
            print(f"[info] CVEFixes-derived loaded counts={counts} total_rows={len(out)}")
            if out:
                return out
        except Exception as e:
            print(f"[warn] {name}: {e}")
    return out


def try_load_securityeval(max_samples: int = 500) -> List[Dict]:
    """Load SecurityEval insecure snippets (Python CWE prompts) as vuln positives."""
    if max_samples <= 0:
        return []
    try:
        from datasets import load_dataset
    except ImportError:
        print("[warn] datasets not installed — skip SecurityEval")
        return []

    for name in ("s2e-lab/SecurityEval", "moyix/SecurityEval"):
        try:
            print(f"[info] trying SecurityEval: {name}")
            ds = load_dataset(name, trust_remote_code=True)
            split = ds["train"] if "train" in ds else ds[list(ds.keys())[0]]
            rows = []
            for i, ex in enumerate(split):
                code = ex.get("Insecure_code") or ex.get("insecure_code") or ex.get("code")
                if not code:
                    continue
                cwe = "CWE-000"
                sid = str(ex.get("ID") or ex.get("id") or i)
                m = re.search(r"(CWE-\d+)", sid, re.I)
                if m:
                    cwe = m.group(1).upper()
                rows.append(
                    {
                        "id": f"seceval-{i}",
                        "language": "python",
                        "cwe": cwe,
                        "code": str(code)[:4000],
                        "label": 1,
                        "source": f"hf:{name}",
                    }
                )
                if len(rows) >= max_samples:
                    break
            print(f"[info] loaded {len(rows)} SecurityEval insecure samples")
            return rows
        except Exception as e:
            print(f"[warn] SecurityEval {name}: {e}")
    return []


def to_detector_rows(pairs: List[Dict], hard_negs: List[Dict]) -> List[Dict]:
    out = []
    for p in pairs:
        out.append(
            {
                "id": f"{p['id']}__vuln",
                "language": p["language"],
                "cwe": p.get("cwe", "CWE-000"),
                "code": p["vulnerable_code"],
                "label": 1,
                "source": "curated_vuln",
            }
        )
        out.append(
            {
                "id": f"{p['id']}__safe",
                "language": p["language"],
                "cwe": p.get("cwe", "CWE-000"),
                "code": p["secure_code"],
                "label": 0,
                "source": "curated_secure",
            }
        )
    for hn in hard_negs:
        out.append(
            {
                "id": hn["id"],
                "language": hn["language"],
                "cwe": hn.get("cwe", "CWE-000"),
                "code": hn["code"],
                "label": 0,
                "source": "hard_negative",
                "why_safe": hn.get("why_safe", ""),
            }
        )
    # multiply hard negatives (critical for low FP)
    more = []
    for hn in hard_negs:
        for k in range(2):
            more.append(
                {
                    "id": f"{hn['id']}__aug{k}",
                    "language": hn["language"],
                    "cwe": hn.get("cwe", "CWE-000"),
                    "code": hn["code"] + ("" if k == 0 else "\n// safe pattern"),
                    "label": 0,
                    "source": "hard_negative_aug",
                }
            )
    return out + more


def to_sft_rows(pairs: List[Dict]) -> List[Dict]:
    sft = []
    for p in pairs:
        lang = p["language"]
        cwe = p.get("cwe", "CWE-000")
        vuln = p["vulnerable_code"]
        sft.append(
            {
                "task": "detect",
                "instruction": "Classify if the code has a security vulnerability. Reply with VULNERABLE or SAFE, then CWE if vulnerable.",
                "input": f"Language: {lang}\nCode:\n{vuln}",
                "output": f"VULNERABLE\n{cwe}\n{p.get('explanation', '')}",
            }
        )
        sft.append(
            {
                "task": "detect",
                "instruction": "Classify if the code has a security vulnerability. Reply with VULNERABLE or SAFE, then CWE if vulnerable.",
                "input": f"Language: {lang}\nCode:\n{p['secure_code']}",
                "output": "SAFE",
            }
        )
        sft.append(
            {
                "task": "explain",
                "instruction": "Explain the vulnerability, impact, and a short attack scenario.",
                "input": f"Language: {lang}\nCWE: {cwe}\nCode:\n{vuln}",
                "output": p.get("explanation", "Security vulnerability present."),
            }
        )
        sft.append(
            {
                "task": "fix",
                "instruction": "Rewrite the vulnerable code into a secure version. Return only code.",
                "input": f"Language: {lang}\nCWE: {cwe}\nVulnerable code:\n{vuln}",
                "output": p["secure_code"],
            }
        )
    # hard neg detect as SAFE
    for hn in all_hard_negatives():
        sft.append(
            {
                "task": "detect",
                "instruction": "Classify if the code has a security vulnerability. Reply with VULNERABLE or SAFE, then CWE if vulnerable.",
                "input": f"Language: {hn['language']}\nCode:\n{hn['code']}",
                "output": "SAFE",
            }
        )
    return sft


def try_load_devign(max_samples: int, seed: int = 42) -> List[Dict]:
    """Load Devign / CodeXGLUE defect detection if datasets lib + network available."""
    if max_samples <= 0:
        return []
    try:
        from datasets import load_dataset
    except ImportError:
        print("[warn] datasets not installed — skip Devign download")
        return []

    candidates = [
        ("google/code_x_glue_cc_defect_detection", None),
        ("DetectVul/devign", None),
        ("claudios/code_x_glue_cc_defect_detection", None),
    ]
    random.seed(seed)
    for name, config in candidates:
        try:
            print(f"[info] trying HuggingFace dataset: {name}")
            ds = load_dataset(name, config, trust_remote_code=True) if config else load_dataset(name, trust_remote_code=True)
            # normalize split
            split = ds["train"] if "train" in ds else ds[list(ds.keys())[0]]
            rows = []
            for i, ex in enumerate(split):
                code = ex.get("func") or ex.get("code") or ex.get("function") or ex.get("text")
                label = ex.get("target") if "target" in ex else ex.get("label")
                if code is None or label is None:
                    continue
                label = int(label)
                rows.append(
                    {
                        "id": f"devign-{i}",
                        "language": "c",
                        "cwe": "CWE-000",
                        "code": str(code)[:4000],
                        "label": label,
                        "source": f"hf:{name}",
                    }
                )
                if len(rows) >= max_samples:
                    break
            print(f"[info] loaded {len(rows)} from {name}")
            return rows
        except Exception as e:
            print(f"[warn] failed {name}: {e}")
            continue
    print("[warn] No Devign dataset downloaded — using curated only")
    return []


def split_rows(rows: List[Dict], seed: int = 42) -> Tuple[List, List, List]:
    random.seed(seed)
    rows = list(rows)
    random.shuffle(rows)
    n = len(rows)
    n_train = int(n * 0.8)
    n_valid = int(n * 0.1)
    train = rows[:n_train]
    valid = rows[n_train : n_train + n_valid]
    test = rows[n_train + n_valid :]
    return train, valid, test


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=HERE / "processed")
    ap.add_argument("--max-devign", type=int, default=4000, help="0 to skip HF Devign")
    ap.add_argument("--max-securityeval", type=int, default=500, help="0 to skip SecurityEval")
    ap.add_argument("--max-cvefixes-lang", type=int, default=200, help="max vuln samples per lang from CVEFixes HF")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    pairs = expand_curated(args.seed)
    hn = all_hard_negatives()
    det = to_detector_rows(pairs, hn)
    det += try_load_devign(args.max_devign, args.seed)
    det += try_load_securityeval(args.max_securityeval)
    det += try_load_cvefixes_langs(args.max_cvefixes_lang)

    # balance-ish: if too many safe from hard neg, ok — we WANT more safe for low FP
    train, valid, test = split_rows(det, args.seed)
    out = args.out
    out.mkdir(parents=True, exist_ok=True)
    n1 = write_jsonl(out / "detector" / "train.jsonl", train)
    n2 = write_jsonl(out / "detector" / "valid.jsonl", valid)
    n3 = write_jsonl(out / "detector" / "test.jsonl", test)
    write_jsonl(out / "hard_negatives.jsonl", hn)
    sft = to_sft_rows(pairs)
    n4 = write_jsonl(out / "sft.jsonl", sft)

    label_counts = Counter(r["label"] for r in det)
    source_counts = Counter(r.get("source", "?") for r in det)
    meta = {
        "detector_total": len(det),
        "detector_train": n1,
        "detector_valid": n2,
        "detector_test": n3,
        "sft_examples": n4,
        "label_counts": dict(label_counts),
        "source_counts": dict(source_counts),
        "pair_count": len(pairs),
        "hard_negative_templates": len(hn),
        "vibe_curated": len(VIBE_CURATED),
        "hardware_note": "RTX3050-4GB + CodeBERT detector + CodeT5-base LoRA",
    }
    (out / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(json.dumps(meta, indent=2))
    print(f"[done] wrote datasets under {out}")


if __name__ == "__main__":
    main()
