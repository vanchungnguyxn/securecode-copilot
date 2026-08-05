"""LLM providers for explain & fix — heuristic / openai / local."""

from __future__ import annotations

import re
import textwrap
from typing import List, Optional

import httpx

from app.core.config import Settings
from app.models.schemas import Explanation, FixSuggestion, Vulnerability
from app.scanners.rules import ALL_RULES
from app.services.repo_ingest import context_window


class BaseLLM:
    async def explain(self, code: str, vuln: Vulnerability) -> Explanation:
        raise NotImplementedError

    async def fix(self, code: str, vuln: Vulnerability) -> FixSuggestion:
        raise NotImplementedError


def _rule_fix_hint(rule_id: str) -> str:
    for r in ALL_RULES:
        if r.rule_id == rule_id:
            return r.fix_hint
    return "Áp dụng nguyên tắc least privilege và validate/sanitize input."


def _explain_for_rule(vuln: Vulnerability, tip: str) -> tuple[str, str, str, List[str]]:
    """Rule-aware explain text (avoid generic 'attacker payload' for secrets)."""
    rid = (vuln.rule_id or "").upper()
    snip = (vuln.snippet or "").strip()
    sev = vuln.severity.value.upper() if hasattr(vuln.severity, "value") else str(vuln.severity).upper()
    cwe = vuln.cwe or "CWE-000"

    if "HARDCODE" in rid or "SECRET" in rid:
        has_fallback = bool(re.search(r"\|\|\s*['\"]", snip))
        why = (
            f"Vấn đề: {vuln.title} ({cwe}) tại dòng {vuln.start_line}.\n\n"
            + (
                "Ứng dụng có đọc biến môi trường, nhưng vẫn để giá trị dự phòng cứng trong mã nguồn. "
                "Khi cấu hình thiếu hoặc deploy quên gán env, hệ thống tự chuyển sang chuỗi đã nằm sẵn "
                "trên Git — tức là bí mật không còn do tổ chức kiểm soát, mà ai có repo cũng biết.\n\n"
                "Về bản chất đây vẫn là hard-coded credential: môi trường chỉ là lớp ưu tiên, "
                "còn cơ chế dự phòng lại phụ thuộc vào một hằng số công khai."
                if has_fallback
                else "Bí mật xác thực được ghi trực tiếp trong mã nguồn. Bất kỳ ai truy cập repo, "
                "artifact CI, hoặc bản backup đều nắm được credential — trái với nguyên tắc "
                "secrets nằm ngoài codebase."
            )
        )
        impact = (
            f"Mức độ: {sev}. Lộ secret làm suy yếu lớp xác thực và toàn vẹn phiên làm việc: "
            "kẻ tấn công có thể đăng nhập bằng mật khẩu mặc định, giả mạo cookie/session đã ký, "
            "hoặc mở rộng đặc quyền quản trị tùy ngữ cảnh (admin panel, API, JWT)."
        )
        attack = (
            "1) Thu thập — đọc mã nguồn / lịch sử Git / log CI và trích giá trị mặc định.\n"
            "2) Điều kiện — môi trường chạy thiếu biến cấu hình nên ứng dụng dùng đúng giá trị đó.\n"
            "3) Khai thác — đăng nhập admin hoặc giả mạo phiên để thao tác trái phép."
        )
        tips = [
            "Chỉ lấy secret từ biến môi trường hoặc secret manager; không gắn fallback trong code.",
            "Thiếu cấu hình thì dừng sớm (throw / exit) thay vì chạy với giá trị mặc định.",
            "Sinh chuỗi đủ dài, ngẫu nhiên; đưa vào .env / vault và đảm bảo không bị commit.",
        ]
        return why, impact, attack, tips

    if "SQLI" in rid:
        why = (
            f"{vuln.message}\n\n"
            "Truy vấn được dựng bằng nối chuỗi / f-string với dữ liệu bên ngoài, "
            "nên kẻ tấn công có thể chèn mệnh đề SQL."
        )
        impact = f"Mức độ: {sev}. Có thể đọc/sửa cơ sở dữ liệu, vượt qua đăng nhập, thậm chí RCE tùy cấu hình DB."
        attack = (
            "1) Attacker gửi tham số dạng 1 OR 1=1 hoặc UNION SELECT.\n"
            f"2) Đoạn tại dòng {vuln.start_line} ghép thẳng vào câu SQL.\n"
            f"3) Cơ sở dữ liệu thực thi payload — kích hoạt {cwe}."
        )
        return why, impact, attack, [tip, "Luôn bind parameter (?, $1).", "Least privilege DB user."]

    if "CMDI" in rid:
        why = (
            f"{vuln.message}\n\n"
            "Lệnh hệ thống nhận chuỗi từ người dùng nên có thể bị chèn thêm lệnh shell."
        )
        impact = f"Mức độ: {sev}. Thực thi mã trên máy chủ, đọc secret, hoặc mở rộng tấn công trong mạng nội bộ."
        attack = (
            "1) Attacker gửi tham số chứa ; hoặc | cùng lệnh hệ thống.\n"
            f"2) os.system/exec tại dòng {vuln.start_line} chạy nguyên chuỗi.\n"
            f"3) Shell thực thi — {cwe}."
        )
        return why, impact, attack, [tip, "Dùng argv list, không shell=True.", "Whitelist argument."]

    if "DESER" in rid:
        why = (
            f"{vuln.message}\n\n"
            "Deserialize đối tượng không tin cậy (pickle/yaml.load) có thể kích hoạt gadget dẫn tới RCE."
        )
        impact = f"Mức độ: {sev}. Remote Code Execution nếu attacker kiểm soát payload."
        attack = (
            "1) Attacker gửi pickle/YAML độc.\n"
            f"2) loads() tại dòng {vuln.start_line} dựng object độc.\n"
            "3) Gadget chạy mã trên máy chủ."
        )
        return why, impact, attack, [tip, "Dùng json / yaml.safe_load.", "Không pickle dữ liệu không tin cậy."]

    why = (
        f"{vuln.message}\n\n"
        f"Điểm này liên quan {cwe} — {vuln.title}."
    )
    impact = (
        f"Mức độ: {sev}. Có thể dẫn tới lộ dữ liệu, chiếm quyền, "
        "hoặc phá vỡ tính toàn vẹn tùy loại lỗ hổng."
    )
    attack = (
        f"1) Attacker tương tác với input/luồng liên quan dòng {vuln.start_line}.\n"
        f"2) Ứng dụng xử lý không kiểm soát đủ.\n"
        f"3) Kích hoạt {cwe} — {vuln.title}."
    )
    return why, impact, attack, [tip, "Validate & sanitize input bên ngoài.", "Áp dụng least privilege."]


def _replace_lines(code: str, start: int, end: int, new_block: str) -> str:
    lines = code.splitlines(keepends=True)
    # normalize new_block newlines
    if not new_block.endswith("\n") and code.endswith("\n"):
        new_block += "\n"
    elif "\n" not in new_block and lines and lines[0].endswith("\n"):
        new_block += "\n"
    before = lines[: max(0, start - 1)]
    after = lines[end:]
    return "".join(before) + new_block + "".join(after)


def _make_diff(original_snippet: str, fixed: str, start_line: int) -> str:
    out = []
    for i, line in enumerate(original_snippet.splitlines(), start=start_line):
        out.append(f"- {line}")
    for i, line in enumerate(fixed.splitlines(), start=start_line):
        out.append(f"+ {line}")
    return "\n".join(out)


class HeuristicLLM(BaseLLM):
    """Deterministic explain/fix for offline demo (thesis-ready, no GPU)."""

    async def explain(self, code: str, vuln: Vulnerability) -> Explanation:
        tip = _rule_fix_hint(vuln.rule_id)
        why, impact, attack, tips = _explain_for_rule(vuln, tip)
        return Explanation(
            vulnerability_id=vuln.id,
            summary=f"{vuln.title} ({vuln.cwe}) tại dòng {vuln.start_line}.",
            why_vulnerable=why,
            impact=impact,
            attack_scenario=attack,
            references=[
                f"https://cwe.mitre.org/data/definitions/{vuln.cwe.replace('CWE-', '')}.html",
                f"https://owasp.org/Top10/",
                f"Rule: {vuln.rule_id}",
            ],
            secure_coding_tips=tips,
        )

    async def fix(self, code: str, vuln: Vulnerability) -> FixSuggestion:
        fixed_snippet = self._synthesize_fix(vuln)
        return FixSuggestion(
            vulnerability_id=vuln.id,
            strategy="pattern-guided-rewrite",
            description=_rule_fix_hint(vuln.rule_id),
            fixed_code=fixed_snippet,
            diff=_make_diff(vuln.snippet, fixed_snippet, vuln.start_line),
            confidence=0.82,
        )

    def _synthesize_fix(self, vuln: Vulnerability) -> str:
        snip = vuln.snippet
        rid = vuln.rule_id
        lang = vuln.language

        if rid.startswith("PY-SQLI") or "SQLI" in rid and lang == "python":
            return textwrap.dedent(
                """\
                # SECURE: parameterized query
                cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
                """
            ).rstrip()

        if rid.startswith("PY-CMDI"):
            return textwrap.dedent(
                """\
                import shlex
                import subprocess
                # SECURE: no shell, whitelist args
                subprocess.run(["ls", "-la", shlex.quote(safe_path)], check=True)
                """
            ).rstrip()

        if rid.startswith("PY-DESER"):
            return textwrap.dedent(
                """\
                import json
                # SECURE: avoid pickle; use JSON
                data = json.loads(user_payload)
                """
            ).rstrip()

        if rid.startswith("PY-EVAL"):
            return textwrap.dedent(
                """\
                import ast
                # SECURE: only parse literals
                value = ast.literal_eval(user_input)
                """
            ).rstrip()

        if "HARDCODE" in rid:
            return self._fix_hardcode(snip, lang if "JS-" not in rid else "javascript")

        if rid.startswith("PY-PATH"):
            return textwrap.dedent(
                """\
                import os
                BASE = "/var/data"
                candidate = os.path.realpath(os.path.join(BASE, user_path))
                if not candidate.startswith(BASE):
                    raise ValueError("Path traversal blocked")
                with open(candidate, "r", encoding="utf-8") as f:
                    content = f.read()
                """
            ).rstrip()

        if rid.startswith("JS-XSS"):
            return textwrap.dedent(
                """\
                // SECURE: avoid innerHTML; use textContent or sanitize
                el.textContent = userInput;
                // or: el.innerHTML = DOMPurify.sanitize(userInput);
                """
            ).rstrip()

        if rid.startswith("JS-SQLI"):
            return textwrap.dedent(
                """\
                // SECURE: parameterized query
                await db.query("SELECT * FROM users WHERE id = $1", [userId]);
                """
            ).rstrip()

        if rid.startswith("JS-CMDI"):
            return textwrap.dedent(
                """\
                const { execFile } = require("child_process");
                // SECURE: execFile without shell
                execFile("ls", ["-la", safePath], (err, stdout) => { /* ... */ });
                """
            ).rstrip()

        if rid.startswith("JS-EVAL"):
            return textwrap.dedent(
                """\
                // SECURE: never eval user strings
                const data = JSON.parse(userInput);
                """
            ).rstrip()

        if rid.startswith("JAVA-SQLI"):
            return textwrap.dedent(
                """\
                // SECURE: PreparedStatement
                PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
                ps.setInt(1, userId);
                ResultSet rs = ps.executeQuery();
                """
            ).rstrip()

        if rid.startswith("JAVA-CMDI"):
            return textwrap.dedent(
                """\
                // SECURE: ProcessBuilder with fixed command + args
                ProcessBuilder pb = new ProcessBuilder("ls", "-la", safePath);
                pb.redirectErrorStream(true);
                Process p = pb.start();
                """
            ).rstrip()

        if rid.startswith("JAVA-XXE"):
            return textwrap.dedent(
                """\
                DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
                dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
                dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
                dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
                dbf.setXIncludeAware(false);
                dbf.setExpandEntityReferences(false);
                """
            ).rstrip()

        if rid.startswith("JAVA-DESER"):
            return textwrap.dedent(
                """\
                // SECURE: avoid ObjectInputStream for untrusted data — use JSON
                ObjectMapper mapper = new ObjectMapper();
                MyDto dto = mapper.readValue(inputStream, MyDto.class);
                """
            ).rstrip()

        if rid.startswith("C-BOF"):
            return textwrap.dedent(
                """\
                /* SECURE: bounded copy */
                char dst[64];
                snprintf(dst, sizeof(dst), "%s", src);
                """
            ).rstrip()

        if rid.startswith("C-FMT"):
            return textwrap.dedent(
                """\
                /* SECURE: fixed format string */
                printf("%s", user_input);
                """
            ).rstrip()

        if rid.startswith("C-CMDI"):
            return textwrap.dedent(
                """\
                /* SECURE: avoid system(); use execve with argv */
                char *argv[] = {"/bin/ls", "-la", safe_path, NULL};
                execve(argv[0], argv, environ);
                """
            ).rstrip()

        # Generic comment-wrap fix
        comment = "#" if lang in ("python",) else ("//" if lang in ("javascript", "typescript", "java", "c", "cpp") else "#")
        return f"{comment} TODO: { _rule_fix_hint(rid) }\n{snip}"

    def _fix_hardcode(self, snip: str, lang: str) -> str:
        """Context-aware secret rewrite — not a one-size API_KEY template."""
        s = snip or ""
        low = s.lower()
        is_js = lang in ("javascript", "typescript")

        # env || 'literal-fallback' (session secret, admin password, …)
        m_fb = re.search(
            r"(?:process\.env\.(?P<env>[A-Z0-9_]+)|os\.environ(?:\[|\.get\()?['\"]?(?P<pyenv>[A-Z0-9_]+))"
            r"[^\n]{0,40}\|\|\s*['\"][^'\"]+['\"]",
            s,
            re.I,
        )
        if m_fb:
            env_key = m_fb.group("env") or m_fb.group("pyenv") or "SECRET"
            if "secret:" in low or "session" in low:
                if is_js:
                    return textwrap.dedent(
                        f"""\
                        // SECURE: require env — no hardcoded session secret fallback
                        secret: (() => {{
                          const value = process.env.{env_key};
                          if (!value) throw new Error("{env_key} must be set");
                          return value;
                        }})(),
                        """
                    ).rstrip()
            if is_js:
                return textwrap.dedent(
                    f"""\
                    // SECURE: require env — no hardcoded fallback
                    const value = process.env.{env_key};
                    if (!value) throw new Error("{env_key} must be set");
                    """
                ).rstrip()
            return textwrap.dedent(
                f"""\
                import os
                # SECURE: require env — no hardcoded fallback
                value = os.environ["{env_key}"]
                """
            ).rstrip()

        # Connection / DB URI with literal credentials
        if re.search(r"(?:mysql|postgres|mongodb|redis)(?:\+\w+)?://", low) or "connectionstring" in low.replace(" ", ""):
            if is_js:
                return textwrap.dedent(
                    """\
                    // SECURE: connection string from env — no embedded password
                    const databaseUrl = process.env.DATABASE_URL;
                    if (!databaseUrl) throw new Error("DATABASE_URL is required");
                    """
                ).rstrip()
            return textwrap.dedent(
                """\
                import os
                # SECURE: full URI from env (or build from DB_USER/DB_PASSWORD env vars)
                DATABASE_URL = os.environ["DATABASE_URL"]
                # engine = create_engine(DATABASE_URL)
                """
            ).rstrip()

        # Prefer keep left-hand name when assigning a literal secret
        m = re.search(
            r"(?P<name>(?:SECRET_KEY|JWT_SECRET|AWS_SECRET_ACCESS_KEY|api_key|API_KEY|"
            r"password|passwd|secret|access_token|private_key|SECRET|TOKEN))"
            r"\s*=\s*['\"][^'\"]+['\"]",
            s,
            re.I,
        )
        if m:
            name = m.group("name")
            env_key = re.sub(r"[^A-Za-z0-9]+", "_", name).upper().strip("_") or "SECRET"
            if is_js:
                return (
                    f"// SECURE: load from environment — no literal\n"
                    f"const {name} = process.env.{env_key};\n"
                    f"if (!{name}) throw new Error(\"{env_key} must be set\");"
                )
            return textwrap.dedent(
                f"""\
                import os
                # SECURE: load from environment / secret manager
                {name} = os.environ["{env_key}"]
                """
            ).rstrip()

        if is_js:
            return textwrap.dedent(
                """\
                // SECURE: load from environment
                const secret = process.env.SESSION_SECRET;
                if (!secret) throw new Error("SESSION_SECRET must be set");
                """
            ).rstrip()
        return textwrap.dedent(
            """\
            import os
            # SECURE: load from environment
            secret = os.environ["SECRET_KEY"]
            """
        ).rstrip()


class OpenAILLM(BaseLLM):
    def __init__(self, api_key: str, model: str):
        self.api_key = api_key
        self.model = model

    async def _chat(self, system: str, user: str) -> str:
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {self.api_key}"},
                json={
                    "model": self.model,
                    "temperature": 0.1,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                },
            )
            resp.raise_for_status()
            data = resp.json()
            return data["choices"][0]["message"]["content"]

    async def explain(self, code: str, vuln: Vulnerability) -> Explanation:
        prompt = (
            f"Language: {vuln.language}\nCWE: {vuln.cwe}\nOWASP: {vuln.owasp}\n"
            f"Title: {vuln.title}\nSnippet:\n{vuln.snippet}\n\n"
            "Trả lời tiếng Việt, các mục: SUMMARY|, WHY|, IMPACT|, ATTACK|, TIPS| (mỗi tip 1 dòng sau TIPS|)."
        )
        text = await self._chat(
            "Bạn là chuyên gia AppSec. Giải thích lỗ hổng ngắn gọn, chính xác.",
            prompt,
        )
        # Fallback parse loosely
        fallback = HeuristicLLM()
        base = await fallback.explain(code, vuln)
        return Explanation(
            vulnerability_id=vuln.id,
            summary=_extract(text, "SUMMARY|", base.summary),
            why_vulnerable=_extract(text, "WHY|", base.why_vulnerable),
            impact=_extract(text, "IMPACT|", base.impact),
            attack_scenario=_extract(text, "ATTACK|", base.attack_scenario),
            references=base.references,
            secure_coding_tips=_extract_list(text, "TIPS|", base.secure_coding_tips),
        )

    async def fix(self, code: str, vuln: Vulnerability) -> FixSuggestion:
        prompt = (
            f"Sửa lỗ hổng {vuln.rule_id} ({vuln.title}) trong code {vuln.language}.\n"
            f"Snippet:\n{vuln.snippet}\n\n"
            "Chỉ trả về đoạn code đã sửa, không markdown."
        )
        try:
            fixed = await self._chat(
                "Bạn là senior secure coding engineer. Chỉ trả về code an toàn.",
                prompt,
            )
            fixed = fixed.strip()
            if fixed.startswith("```"):
                fixed = "\n".join(fixed.splitlines()[1:])
                if fixed.endswith("```"):
                    fixed = "\n".join(fixed.splitlines()[:-1])
        except Exception:
            return await HeuristicLLM().fix(code, vuln)

        return FixSuggestion(
            vulnerability_id=vuln.id,
            strategy="llm-rewrite",
            description=_rule_fix_hint(vuln.rule_id),
            fixed_code=fixed.strip(),
            diff=_make_diff(vuln.snippet, fixed.strip(), vuln.start_line),
            confidence=0.78,
        )


class LocalLLM(BaseLLM):
    """Fine-tuned CodeT5 LoRA for explain/fix — fallback heuristic nếu chưa train."""

    def __init__(self, model_path: str = ""):
        self._fallback = HeuristicLLM()
        self._gen = None
        try:
            from app.services.ml_models import get_generator

            self._gen = get_generator()
        except Exception:
            self._gen = None

    @property
    def ready(self) -> bool:
        if not (self._gen and self._gen.available):
            return False
        # Checkpoint path alone is not enough — runtime needs torch/peft in this venv
        try:
            import peft  # noqa: F401
            import torch  # noqa: F401
            import transformers  # noqa: F401

            return True
        except Exception:
            return False

    def _vuln_block(self, code: str, vuln: Vulnerability) -> str:
        """Prefer padded window so model sees imports / env usage around the hit."""
        snip = (vuln.snippet or "").strip()
        if not code or not vuln.start_line:
            return snip
        try:
            ctx = context_window(code, vuln.start_line, vuln.end_line or vuln.start_line, pad=10).strip()
            if ctx and len(ctx) >= len(snip):
                return ctx
        except Exception:
            pass
        return snip

    async def explain(self, code: str, vuln: Vulnerability) -> Explanation:
        base = await self._fallback.explain(code, vuln)
        rid = (vuln.rule_id or "").upper()
        # HARDCODE/auth secret: heuristic text is more accurate than weak CodeT5 prose
        if "HARDCODE" in rid or "SECRET" in rid or "PLAINPWD" in rid:
            return base
        if not self.ready:
            return base
        try:
            # Instruction must match SFT format in prepare_datasets.to_sft_rows
            text = self._gen.generate(
                "Explain the vulnerability, impact, and a short attack scenario.",
                f"Language: {vuln.language}\nCWE: {vuln.cwe}\nCode:\n{self._vuln_block(code, vuln)}",
                max_new_tokens=128,
                num_beams=2,
            )
            why = (text or "").strip()
            # Reject code-like / repetitive garbage (common CodeT5 failure mode)
            if why and len(why) > 24 and _text_looks_usable_explanation(why):
                return Explanation(
                    vulnerability_id=vuln.id,
                    summary=base.summary,
                    why_vulnerable=why[:1200],
                    impact=base.impact,
                    attack_scenario=base.attack_scenario,
                    references=base.references,
                    secure_coding_tips=base.secure_coding_tips,
                )
        except Exception:
            pass
        return base

    async def fix(self, code: str, vuln: Vulnerability) -> FixSuggestion:
        hint = _rule_fix_hint(vuln.rule_id)
        heuristic = await self._fallback.fix(code, vuln)
        rid = (vuln.rule_id or "").upper()
        # Prefer deterministic rewrite for secrets — CodeT5 often hallucinates here
        if "HARDCODE" in rid or "SECRET" in rid or "PLAINPWD" in rid:
            heuristic.strategy = "pattern-guided-rewrite"
            return heuristic
        if not self.ready:
            heuristic.strategy = "pattern-guided-rewrite"
            return heuristic
        try:
            block = self._vuln_block(code, vuln)
            fixed = self._gen.generate(
                "Rewrite the vulnerable code into a secure version. Return only code.",
                f"Language: {vuln.language}\nCWE: {vuln.cwe}\nVulnerable code:\n{block}",
                max_new_tokens=128,
                num_beams=2,
            ).strip()
            if _is_degenerate_text(fixed):
                heuristic.strategy = "heuristic-fallback"
                heuristic.confidence = 0.80
                return heuristic
            usable = _fix_looks_usable(fixed, vuln)
            if usable:
                return FixSuggestion(
                    vulnerability_id=vuln.id,
                    strategy="codet5-lora",
                    description=hint,
                    fixed_code=fixed,
                    diff=_make_diff(vuln.snippet or block, fixed, vuln.start_line),
                    confidence=0.88,
                )
            heuristic.strategy = "heuristic-fallback"
            heuristic.confidence = 0.80
            return heuristic
        except Exception:
            heuristic.strategy = "heuristic-fallback"
            return heuristic


def _is_degenerate_text(text: str) -> bool:
    """Detect repetition loops like 'import sqlite3' x100."""
    if not text or not text.strip():
        return True
    t = text.strip()
    if len(t) > 2500:
        return True
    # Same line repeated many times
    lines = [ln.strip() for ln in t.splitlines() if ln.strip()]
    if len(lines) >= 6:
        from collections import Counter

        counts = Counter(lines)
        top_n, top_c = counts.most_common(1)[0]
        if top_c >= 4 and top_c / len(lines) >= 0.5:
            return True
        if len(set(lines)) <= 2 and len(lines) >= 5:
            return True
    # Token spam in one long line / paragraph
    compact = re.sub(r"\s+", " ", t)
    # e.g. "import sqlite3 import sqlite3 import sqlite3"
    m = re.findall(r"(\b[\w\.\"']{4,40}\b)(?:\s+\1){3,}", compact, flags=re.I)
    if m:
        return True
    # Repeated phrase chunks (2–8 words)
    if re.search(r"((?:\S+\s+){1,6}\S+)(?:\s+\1){3,}", compact, flags=re.I):
        return True
    if re.search(r"(.{6,80})\1{3,}", compact):
        return True
    # Extremely low unique-token ratio
    toks = re.findall(r"[A-Za-z_]{2,}", t)
    if len(toks) >= 20 and len(set(tok.lower() for tok in toks)) / len(toks) < 0.15:
        return True
    return False


def _text_looks_usable_explanation(text: str) -> bool:
    if _is_degenerate_text(text):
        return False
    low = text.lower()
    # Explain that is mostly code imports is wrong task output
    codeish = sum(1 for k in ("import ", "def ", "return ", "cursor.", "execute(", "os.system") if k in low)
    prose = sum(1 for k in ("vulnerab", "attack", "inject", "risk", "cwe", "exploit", "unsafe", "secure") if k in low)
    if codeish >= 2 and prose == 0:
        return False
    if low.count("import ") >= 3:
        return False
    return True


def _prefer_model_or_heuristic(model_fix: str, heuristic_fix: str, vuln: Vulnerability) -> str:
    """If model output is weak but not empty, keep when it looks more contextual."""
    if _is_degenerate_text(model_fix):
        return heuristic_fix
    if _fix_looks_usable(model_fix, vuln):
        return model_fix
    snip = (vuln.snippet or "").lower()
    mf = model_fix.lower()
    # Model kept similar identifiers / mentions env → prefer model
    if any(tok in mf for tok in ("environ", "getenv", "process.env", "secret manager")):
        return model_fix
    if snip and any(w in mf for w in re.findall(r"[A-Za-z_]{4,}", snip)[:6]):
        return model_fix
    return heuristic_fix


def _fix_looks_usable(fixed: str, vuln: Vulnerability) -> bool:
    """Reject empty / copy-paste vuln / tiny garbage outputs."""
    if not fixed or len(fixed.strip()) < 8:
        return False
    if _is_degenerate_text(fixed):
        return False
    snip = (vuln.snippet or "").strip()
    f = fixed.strip()
    if snip and f.replace(" ", "") == snip.replace(" ", ""):
        return False
    # Reject TODO-only stubs
    if re.match(r"^(?:#|//)\s*TODO:", f) and "\n" not in f.strip():
        return False
    # Hallucinated import soup (e.g. sqlite3 + mysql + sqlalchemy for a one-liner)
    import_lines = [
        ln for ln in f.splitlines()
        if re.match(r"^\s*(?:import|from)\s+", ln)
    ]
    if len(import_lines) >= 3 and not re.search(r"^\s*(?:import|from)\s+", snip, re.M):
        return False
    if len(import_lines) >= 2 and len(f.splitlines()) <= 4:
        # Short "fix" dominated by unrelated imports → prefer heuristic
        if not any(tok in snip.lower() for tok in ("sqlite", "mysql", "sqlalchemy", "json", "subprocess")):
            if sum(1 for x in ("sqlite", "mysql", "sqlalchemy") if x in f.lower()) >= 2:
                return False
    # still contains classic bad APIs without safe counterpart nearby
    bad = {
        "pickle.loads": "json.loads",
        "os.system(": "subprocess",
        "innerHTML": "textContent",
        "shell=True": "shell=False",
    }
    low = f.lower()
    for bad_tok, good_tok in bad.items():
        if bad_tok.lower() in low and good_tok.lower() not in low:
            if bad_tok.lower() in snip.lower():
                return False
    return True


def _extract(text: str, marker: str, default: str) -> str:
    if marker not in text:
        return default
    part = text.split(marker, 1)[1]
    for other in ("SUMMARY|", "WHY|", "IMPACT|", "ATTACK|", "TIPS|"):
        if other != marker and other in part:
            part = part.split(other, 1)[0]
    return part.strip() or default


def _extract_list(text: str, marker: str, default: List[str]) -> List[str]:
    block = _extract(text, marker, "")
    if not block:
        return default
    lines = [ln.strip("-• ").strip() for ln in block.splitlines() if ln.strip()]
    return lines or default


def get_llm(settings: Settings) -> BaseLLM:
    provider = (settings.llm_provider or "heuristic").lower()
    if provider == "openai" and settings.openai_api_key:
        return OpenAILLM(settings.openai_api_key, settings.openai_model)
    if provider == "local":
        return LocalLLM(settings.model_path)
    return HeuristicLLM()
