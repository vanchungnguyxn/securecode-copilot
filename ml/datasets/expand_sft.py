"""Expand multilingual vuln/secure pairs into a large SFT corpus for explain+fix.

Writes:
  ml/datasets/processed/sft.jsonl
  ml/datasets/processed/sft_pairs.jsonl  (raw pairs for audit)
"""

from __future__ import annotations

import argparse
import json
import random
from pathlib import Path
from typing import Any, Dict, List

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]

# Import curated base pairs
import sys

sys.path.insert(0, str(HERE))
from prepare_datasets import (  # noqa: E402
    CURATED,
    HARD_NEGATIVES,
    TEMPLATES_EXPAND,
    expand_curated,
    load_sample_jsonl,
)
from vibe_patterns import VIBE_BULK, VIBE_CURATED, VIBE_HARD_NEGATIVES  # noqa: E402
from lang_extra import LANG_BULK, LANG_CURATED  # noqa: E402

# Extra high-volume templates: (lang, cwe, sev, vuln_tpl, secure_tpl, expl)
# Placeholders: {v}, {id}, {host}, {path}, {expr}
BULK: List[Dict[str, Any]] = []

_PY = [
    (
        "CWE-89",
        "critical",
        'db.execute(f"SELECT * FROM {table} WHERE id = {{{v}}}")',
        'db.execute("SELECT * FROM " + table + " WHERE id = ?", ({v},))',
        "f-string SQL Injection — dùng parameterized query.",
    ),
    (
        "CWE-89",
        "critical",
        'sql = "DELETE FROM users WHERE name=\'" + {v} + "\'"; cur.execute(sql)',
        'cur.execute("DELETE FROM users WHERE name=%s", ({v},))',
        "SQL nối chuỗi — parameterized.",
    ),
    (
        "CWE-78",
        "critical",
        'os.system("nslookup " + {host})',
        'subprocess.run(["nslookup", {host}], check=False)',
        "Command Injection qua os.system.",
    ),
    (
        "CWE-78",
        "critical",
        'subprocess.Popen("cat " + {path}, shell=True)',
        'subprocess.Popen(["cat", {path}])',
        "shell=True + path → injection.",
    ),
    (
        "CWE-502",
        "critical",
        "data = pickle.loads({v})",
        "data = json.loads({v})",
        "pickle.loads không tin cậy → RCE.",
    ),
    (
        "CWE-95",
        "critical",
        "result = eval({expr})",
        "result = ast.literal_eval({expr})",
        "eval arbitrary code.",
    ),
    (
        "CWE-22",
        "high",
        'open(base + "/" + {path}).read()',
        'p = Path(base).joinpath({path}).resolve(); assert str(p).startswith(str(Path(base).resolve())); open(p).read()',
        "Path traversal.",
    ),
    (
        "CWE-798",
        "high",
        'SECRET = "sk-live-{id}abcdef"',
        'SECRET = os.environ["SECRET"]',
        "Hardcoded secret.",
    ),
    (
        "CWE-918",
        "high",
        "requests.get({v})",
        'if urlparse({v}).hostname not in ALLOWED: raise ValueError("ssrf"); requests.get({v})',
        "SSRF nếu URL từ user.",
    ),
]

_JS = [
    (
        "CWE-89",
        "critical",
        "db.query(`SELECT * FROM t WHERE id=${{{v}}}`)",
        'db.query("SELECT * FROM t WHERE id=$1", [{v}])',
        "Template SQL Injection.",
    ),
    (
        "CWE-79",
        "high",
        "el.innerHTML = {v};",
        "el.textContent = {v};",
        "DOM XSS via innerHTML.",
    ),
    (
        "CWE-79",
        "high",
        "document.write({v});",
        "el.textContent = {v};",
        "document.write XSS.",
    ),
    (
        "CWE-78",
        "critical",
        "exec(`ls ${{{v}}}`);",
        'execFile("ls", [{v}]);',
        "Command injection child_process.",
    ),
    (
        "CWE-95",
        "critical",
        "eval({v});",
        "JSON.parse({v});",
        "eval RCE/XSS.",
    ),
    (
        "CWE-22",
        "high",
        "fs.readFileSync(path.join(root, {v}))",
        'const p=path.resolve(root,{v}); if(!p.startsWith(root)) throw Error("deny"); fs.readFileSync(p)',
        "Path traversal.",
    ),
    (
        "CWE-798",
        "high",
        'const API_KEY="sk-{id}-secretkey99";',
        "const API_KEY=process.env.API_KEY;",
        "Hardcoded API key.",
    ),
]

_JAVA = [
    (
        "CWE-89",
        "critical",
        'st.executeQuery("SELECT * FROM u WHERE id=" + {v});',
        'PreparedStatement ps=c.prepareStatement("SELECT * FROM u WHERE id=?"); ps.setString(1,{v});',
        "SQL Injection Statement.",
    ),
    (
        "CWE-78",
        "critical",
        'Runtime.getRuntime().exec("ping " + {host});',
        'new ProcessBuilder("ping","-c","1",{host}).start();',
        "Command Injection Runtime.exec.",
    ),
    (
        "CWE-502",
        "critical",
        "Object o = new ObjectInputStream({v}).readObject();",
        "MyDto o = new ObjectMapper().readValue({v}, MyDto.class);",
        "Insecure deserialization.",
    ),
    (
        "CWE-611",
        "high",
        "DocumentBuilderFactory.newInstance().newDocumentBuilder().parse({v});",
        'DocumentBuilderFactory f=DocumentBuilderFactory.newInstance(); f.setFeature("http://apache.org/xml/features/disallow-doctype-decl",true); f.newDocumentBuilder().parse({v});',
        "XXE risk.",
    ),
    (
        "CWE-79",
        "high",
        "resp.getWriter().print(req.getParameter({v}));",
        "resp.getWriter().print(Encode.forHtml(req.getParameter({v})));",
        "Reflected XSS.",
    ),
]

_C = [
    (
        "CWE-120",
        "critical",
        "strcpy(buf, {v});",
        'snprintf(buf, sizeof(buf), "%s", {v});',
        "Buffer overflow strcpy.",
    ),
    (
        "CWE-120",
        "critical",
        "gets(buf);",
        "fgets(buf, sizeof(buf), stdin);",
        "gets unbounded.",
    ),
    (
        "CWE-134",
        "high",
        "printf({v});",
        'printf("%s", {v});',
        "Format string.",
    ),
    (
        "CWE-78",
        "critical",
        "system({v});",
        'char *argv[]={"/bin/true", NULL}; execve(argv[0], argv, environ);',
        "system() shell injection.",
    ),
    (
        "CWE-89",
        "critical",
        'sprintf(sql, "SELECT * FROM t WHERE id=\'%s\'", {v});',
        "/* use sqlite3_bind_text prepared statement */",
        "SQL via sprintf.",
    ),
]


def _fill(tpl: str, i: int) -> str:
    # Prefer lang placeholders used by csharp bulk
    return (
        tpl.replace("{v}", f"user_input_{i}")
        .replace("{id}", f"{i:04d}")
        .replace("{host}", f"host_{i}")
        .replace("{path}", f"path_{i}")
        .replace("{expr}", f"expr_{i}")
        .replace("{table}", "accounts" if i % 2 == 0 else "orders")
    )


def build_bulk(n_per_template: int = 8) -> List[Dict[str, Any]]:
    rows = []
    packs = [
        ("python", _PY),
        ("javascript", _JS),
        ("java", _JAVA),
        ("c", _C),
    ]
    # merge vibe-code + php/csharp/cpp bulk templates
    for lang, items in VIBE_BULK.items():
        packs.append((lang, items))
    for lang, items in LANG_BULK.items():
        packs.append((lang, items))

    idx = 0
    for lang, items in packs:
        for cwe, sev, vuln_t, secure_t, expl in items:
            for k in range(n_per_template):
                idx += 1
                rows.append(
                    {
                        "id": f"bulk-{lang}-{idx}",
                        "language": lang,
                        "cwe": cwe,
                        "severity": sev,
                        "vulnerable_code": _fill(vuln_t, idx),
                        "secure_code": _fill(secure_t, idx),
                        "explanation": (
                            f"{expl} Impact: có thể chiếm quyền / lộ dữ liệu. "
                            f"Attack: attacker kiểm soát input liên quan CWE {cwe}."
                        ),
                    }
                )
    return rows


def rich_explain(p: Dict[str, Any]) -> str:
    return (
        f"Summary: {p.get('explanation', 'Vulnerability detected.')}\n"
        f"CWE: {p.get('cwe')}\n"
        f"Impact: Unauthorized access, data leakage, or code execution depending on {p.get('cwe')}.\n"
        f"Attack: Craft malicious input reaching the vulnerable statement.\n"
        f"Fix hint: Replace unsafe pattern with the secure counterpart in the paired example."
    )


def to_sft(pairs: List[Dict[str, Any]], hard: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    sft = []
    for p in pairs:
        lang, cwe = p["language"], p.get("cwe", "CWE-000")
        vuln, secure = p["vulnerable_code"], p["secure_code"]
        sft.extend(
            [
                {
                    "task": "detect",
                    "instruction": "Classify if the code has a security vulnerability. Reply with VULNERABLE or SAFE, then CWE if vulnerable.",
                    "input": f"Language: {lang}\nCode:\n{vuln}",
                    "output": f"VULNERABLE\n{cwe}",
                },
                {
                    "task": "detect",
                    "instruction": "Classify if the code has a security vulnerability. Reply with VULNERABLE or SAFE, then CWE if vulnerable.",
                    "input": f"Language: {lang}\nCode:\n{secure}",
                    "output": "SAFE",
                },
                {
                    "task": "explain",
                    "instruction": "Explain the vulnerability, impact, and a short attack scenario.",
                    "input": f"Language: {lang}\nCWE: {cwe}\nCode:\n{vuln}",
                    "output": rich_explain(p),
                },
                {
                    "task": "fix",
                    "instruction": (
                        "fix: Rewrite the vulnerable code into a secure version. "
                        "Return only the fixed code, no markdown, no explanation."
                    ),
                    "input": f"Language: {lang}\nCWE: {cwe}\nVulnerable code:\n{vuln}",
                    "output": secure,
                },
            ]
        )
    for hn in hard:
        sft.append(
            {
                "task": "detect",
                "instruction": "Classify if the code has a security vulnerability. Reply with VULNERABLE or SAFE, then CWE if vulnerable.",
                "input": f"Language: {hn['language']}\nCode:\n{hn['code']}",
                "output": "SAFE",
            }
        )
        # also explain why safe briefly for anti-hallucination
        sft.append(
            {
                "task": "explain",
                "instruction": "Explain whether the code is vulnerable. If safe, say why.",
                "input": f"Language: {hn['language']}\nCode:\n{hn['code']}",
                "output": f"SAFE. {hn.get('why_safe', 'Uses a secure API pattern.')}",
            }
        )
    return sft


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=HERE / "processed")
    ap.add_argument("--n-per-template", type=int, default=12)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()
    random.seed(args.seed)

    pairs = expand_curated(args.seed) + build_bulk(args.n_per_template)
    # dedupe
    seen = set()
    uniq = []
    for p in pairs:
        key = (p["language"], p["vulnerable_code"].strip())
        if key in seen:
            continue
        seen.add(key)
        uniq.append(p)

    hard = list(HARD_NEGATIVES) + list(VIBE_HARD_NEGATIVES)
    sft = to_sft(uniq, hard)
    random.shuffle(sft)
    args.out.mkdir(parents=True, exist_ok=True)
    pairs_path = args.out / "sft_pairs.jsonl"
    sft_path = args.out / "sft.jsonl"
    with pairs_path.open("w", encoding="utf-8") as f:
        for p in uniq:
            f.write(json.dumps(p, ensure_ascii=False) + "\n")
    with sft_path.open("w", encoding="utf-8") as f:
        for r in sft:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    by_task = {}
    for r in sft:
        by_task[r["task"]] = by_task.get(r["task"], 0) + 1
    meta = {
        "pairs": len(uniq),
        "sft_examples": len(sft),
        "by_task": by_task,
        "languages": sorted({p["language"] for p in uniq}),
    }
    (args.out / "sft_meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(json.dumps(meta, indent=2))
    print(f"[done] {sft_path}")


if __name__ == "__main__":
    main()
