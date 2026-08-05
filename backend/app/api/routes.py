from fastapi import APIRouter, File, HTTPException, UploadFile

from app.core.config import get_settings
from app.models.schemas import (
    ApplyFixRequest,
    ApplyFixResponse,
    BatchScanRequest,
    ExplainRequest,
    Explanation,
    FixRequest,
    FixSuggestion,
    HealthResponse,
    RepoScanRequest,
    RepoScanResult,
    ScanRequest,
    ScanResult,
)
from app.services.copilot import CopilotService

router = APIRouter()
service = CopilotService()

SUPPORTED = ["python", "javascript", "typescript", "java", "c", "cpp"]


@router.get("/health", response_model=HealthResponse)
async def health():
    s = get_settings()
    return HealthResponse(
        status="ok",
        version=s.app_version,
        llm_provider=s.llm_provider,
        supported_languages=SUPPORTED,
    )


@router.post("/scan", response_model=ScanResult)
async def scan(req: ScanRequest):
    if not req.code.strip():
        raise HTTPException(status_code=400, detail="Code is empty")
    return await service.scan(req)


@router.post("/scan/batch")
async def scan_batch(req: BatchScanRequest):
    results = []
    for f in req.files:
        results.append(await service.scan(f))
    total = sum(r.vulnerability_count for r in results)
    return {"file_count": len(results), "total_vulnerabilities": total, "results": results}


@router.post("/scan/repo", response_model=RepoScanResult)
async def scan_repo(req: RepoScanRequest):
    if not req.github_url:
        raise HTTPException(status_code=400, detail="github_url is required (or use /scan/repo/upload)")
    try:
        return await service.scan_repo(req)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@router.post("/scan/repo/upload", response_model=RepoScanResult)
async def scan_repo_upload(
    file: UploadFile = File(...),
    include_explanations: bool = True,
    include_fixes: bool = True,
    max_files: int = 300,
    ml_discovery: bool = False,
    max_enrich: int = 80,
):
    if not file.filename or not file.filename.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="Upload a .zip of the repository")
    data = await file.read()
    if len(data) > 80 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="Zip too large (max 80MB)")
    req = RepoScanRequest(
        include_explanations=include_explanations,
        include_fixes=include_fixes,
        max_files=max_files,
        ml_discovery=ml_discovery,
        max_enrich=max_enrich,
    )
    try:
        return await service.scan_repo(req, zip_bytes=data)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@router.post("/explain", response_model=Explanation)
async def explain(req: ExplainRequest):
    return await service.explain(req.code, req.vulnerability)


@router.post("/fix", response_model=FixSuggestion)
async def fix(req: FixRequest):
    return await service.fix(req.code, req.vulnerability)


@router.post("/apply-fix", response_model=ApplyFixResponse)
async def apply_fix(req: ApplyFixRequest):
    return service.apply_fix(req.code, req.fixed_snippet, req.start_line, req.end_line)


@router.get("/rules")
async def list_rules():
    from app.scanners.rules import ALL_RULES

    return {
        "count": len(ALL_RULES),
        "rules": [
            {
                "rule_id": r.rule_id,
                "title": r.title,
                "severity": r.severity,
                "cwe": r.cwe,
                "owasp": r.owasp,
                "languages": r.languages,
            }
            for r in ALL_RULES
        ],
    }
