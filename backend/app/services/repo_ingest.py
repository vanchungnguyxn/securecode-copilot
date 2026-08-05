"""Ingest local folders, zip uploads, or GitHub repos for multi-file scanning."""

from __future__ import annotations

import io
import re
import zipfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import httpx

from app.scanners.rules import detect_language

SKIP_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    "dist",
    "build",
    ".idea",
    ".vscode",
    "target",
    "vendor",
    ".venv-ml",
    "coverage",
    ".next",
    ".nuxt",
    "Pods",
    "bin",
    "obj",
}

# Prefer application / API paths when capping file count
PRIORITY_DIR_MARKERS = (
    "/app/",
    "/src/",
    "/backend/",
    "/server/",
    "/api/",
    "/routes/",
    "/controllers/",
    "/services/",
    "/handlers/",
    "/lib/",
    "/cmd/",
    "/internal/",
    "/pkg/",
    "/examples/",
    "\\app\\",
    "\\src\\",
    "\\backend\\",
)

EXT_LANG = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".cs": "csharp",
    ".php": "php",
    ".rules": "firebase",
}


def _parse_github(url: str) -> Optional[Tuple[str, str, Optional[str]]]:
    """Return (owner, repo, ref_or_None)."""
    u = url.strip().rstrip("/")
    m = re.match(
        r"https?://github\.com/([^/]+)/([^/]+)(?:/(?:tree|blob)/([^/]+))?",
        u,
        re.I,
    )
    if m:
        owner, repo, ref = m.group(1), m.group(2), m.group(3)
        if repo.endswith(".git"):
            repo = repo[:-4]
        return owner, repo, ref
    m = re.match(r"^([^/\s]+)/([^/\s]+?)(?:\.git)?$", u)
    if m:
        return m.group(1), m.group(2), None
    return None


async def _github_default_branch(owner: str, repo: str) -> Optional[str]:
    api = f"https://api.github.com/repos/{owner}/{repo}"
    try:
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            resp = await client.get(api, headers={"Accept": "application/vnd.github+json"})
            if resp.status_code == 200:
                return (resp.json() or {}).get("default_branch")
    except Exception:
        return None
    return None


async def download_github_zip(url: str, dest: Path) -> Path:
    parsed = _parse_github(url)
    if not parsed:
        raise ValueError("Invalid GitHub URL. Use https://github.com/owner/repo or owner/repo")
    owner, repo, hinted = parsed

    refs: List[str] = []
    if hinted:
        refs.append(hinted)
    default = await _github_default_branch(owner, repo)
    for cand in (default, "main", "master", "develop", "dev"):
        if cand and cand not in refs:
            refs.append(cand)

    last_err: Optional[Exception] = None
    async with httpx.AsyncClient(timeout=180.0, follow_redirects=True) as client:
        for ref in refs:
            for zip_url in (
                f"https://codeload.github.com/{owner}/{repo}/zip/refs/heads/{ref}",
                f"https://codeload.github.com/{owner}/{repo}/zip/refs/tags/{ref}",
                f"https://codeload.github.com/{owner}/{repo}/zip/{ref}",
            ):
                try:
                    resp = await client.get(zip_url)
                    if resp.status_code == 404:
                        continue
                    resp.raise_for_status()
                    data = resp.content
                    if len(data) < 100:
                        continue
                    with zipfile.ZipFile(io.BytesIO(data)) as zf:
                        zf.extractall(dest)
                    kids = [p for p in dest.iterdir() if p.is_dir()]
                    return kids[0] if len(kids) == 1 else dest
                except Exception as e:
                    last_err = e
                    continue

    raise ValueError(
        f"Không tải được GitHub repo {owner}/{repo}. "
        f"Thử URL có /tree/<branch>, kiểm tra repo public. Chi tiết: {last_err}"
    )


def extract_zip_bytes(content: bytes, dest: Path) -> Path:
    with zipfile.ZipFile(io.BytesIO(content)) as zf:
        zf.extractall(dest)
    kids = [p for p in dest.iterdir() if p.is_dir()]
    return kids[0] if len(kids) == 1 else dest


def _priority_score(rel: str) -> Tuple[int, str]:
    low = "/" + rel.replace("\\", "/").lower()
    if any(m.replace("\\", "/") in low for m in PRIORITY_DIR_MARKERS):
        return (0, rel.lower())
    # demote deep nested tests / fixtures slightly but still scan
    if "/test" in low or "/tests/" in low or "/__tests__/" in low:
        return (2, rel.lower())
    return (1, rel.lower())


def iter_source_files(root: Path, max_files: int = 300, max_bytes: int = 800_000) -> List[Dict]:
    """Walk repo thoroughly; prioritize app/src paths when capping."""
    candidates: List[Dict] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        ext = path.suffix.lower()
        if ext not in EXT_LANG:
            continue
        try:
            size = path.stat().st_size
            if size > max_bytes or size == 0:
                continue
            code = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        # skip minified / generated noise
        if ext in {".js", ".mjs", ".cjs"} and size > 120_000 and code.count("\n") < 30:
            continue
        rel = str(path.relative_to(root)).replace("\\", "/")
        lang = EXT_LANG[ext]
        candidates.append({"path": rel, "language": lang, "code": code})

    candidates.sort(key=lambda f: _priority_score(f["path"]))
    return candidates[: max(1, max_files)]


def context_window(code: str, start_line: int, end_line: int, pad: int = 12) -> str:
    """Extract surrounding lines so the classifier 'sees' function/file context."""
    lines = code.splitlines()
    if not lines:
        return ""
    s = max(0, start_line - 1 - pad)
    e = min(len(lines), end_line + pad)
    chunk = lines[s:e]
    text = "\n".join(chunk)
    if len(text) > 3500:
        text = text[:3500]
    return text
