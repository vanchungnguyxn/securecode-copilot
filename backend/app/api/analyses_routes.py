"""Analyses API — quota-gated wrap of CopilotService."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, remaining_usage
from app.db.models import (
    Analysis,
    AnalysisStatus,
    AuditLog,
    Feedback,
    UsageRecord,
    User,
    Vulnerability,
)
from app.db.session import get_db
from app.models.schemas import Language, ScanRequest, ScanResult
from app.services.copilot import CopilotService

router = APIRouter(prefix="/analyses", tags=["analyses"])
service = CopilotService()


class AnalyzeRequest(BaseModel):
    code: str = Field(min_length=1)
    language: str = "python"
    filename: Optional[str] = "untitled.py"
    project_name: Optional[str] = ""
    explain_locale: str = "vi"
    include_explanations: bool = False
    include_fixes: bool = False


class AnalysisSummary(BaseModel):
    id: int
    project_name: str
    filename: str
    language: str
    status: str
    vulnerability_count: int
    highest_severity: Optional[str]
    line_count: int
    created_at: datetime

    model_config = {"from_attributes": True}


class AnalysisDetail(AnalysisSummary):
    source_code: Optional[str] = None
    result: Optional[dict] = None
    explain_locale: str = "vi"
    error_message: Optional[str] = None


class FeedbackRequest(BaseModel):
    analysis_id: Optional[int] = None
    vulnerability_id: Optional[int] = None
    rating: int = Field(ge=1, le=5)
    comment: str = ""


def _sev_rank(s: str) -> int:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return order.get((s or "").lower(), 9)


@router.post("", response_model=AnalysisDetail)
async def create_analysis(
    body: AnalyzeRequest, user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    if remaining_usage(user) <= 0:
        raise HTTPException(
            status_code=402,
            detail={
                "code": "QUOTA_EXCEEDED",
                "message": (
                    "Bạn đã sử dụng hết lượt phân tích trong kỳ hiện tại. "
                    "Hãy nâng cấp gói để tiếp tục sử dụng SecureCode Copilot."
                ),
            },
        )

    plan = user.plan
    max_lines = plan.max_lines if plan else 2000
    line_count = body.code.count("\n") + (1 if body.code.strip() else 0)
    if line_count > max_lines:
        raise HTTPException(
            status_code=400,
            detail=f"Vượt giới hạn {max_lines} dòng của gói hiện tại (file có {line_count} dòng).",
        )

    analysis = Analysis(
        user_id=user.id,
        project_name=(body.project_name or "").strip() or "Untitled",
        filename=body.filename or "untitled.py",
        language=body.language,
        explain_locale=body.explain_locale or "vi",
        status=AnalysisStatus.RUNNING,
        source_code=body.code,
        line_count=line_count,
    )
    db.add(analysis)
    db.commit()
    db.refresh(analysis)

    try:
        try:
            lang = Language(body.language)
        except ValueError:
            lang = Language.AUTO
        req = ScanRequest(
            code=body.code,
            language=lang,
            filename=body.filename,
            include_explanations=body.include_explanations,
            include_fixes=body.include_fixes,
        )
        result: ScanResult = await service.scan(req)
    except Exception as e:
        analysis.status = AnalysisStatus.FAILED
        analysis.error_message = str(e)
        db.add(analysis)
        db.commit()
        raise HTTPException(status_code=500, detail="Phân tích thất bại — chưa trừ lượt sử dụng") from e

    highest = None
    for v in result.vulnerabilities:
        sev = v.severity.value if hasattr(v.severity, "value") else str(v.severity)
        if highest is None or _sev_rank(sev) < _sev_rank(highest):
            highest = sev
        db.add(
            Vulnerability(
                analysis_id=analysis.id,
                external_id=v.id,
                rule_id=v.rule_id,
                title=v.title,
                severity=sev,
                cwe=v.cwe,
                owasp=v.owasp or "",
                start_line=v.start_line,
                end_line=v.end_line,
                snippet=v.snippet or "",
                message=v.message or "",
                confidence=float(v.confidence or 0.8),
            )
        )

    user.used_this_month = int(user.used_this_month) + 1
    db.add(user)
    db.add(UsageRecord(user_id=user.id, analysis_id=analysis.id, units=1))

    payload = result.model_dump() if hasattr(result, "model_dump") else result.dict()
    analysis.status = AnalysisStatus.COMPLETED
    analysis.vulnerability_count = len(result.vulnerabilities)
    analysis.highest_severity = highest
    analysis.result_json = json.dumps(payload, ensure_ascii=False)
    db.add(analysis)
    db.commit()
    db.refresh(analysis)

    return AnalysisDetail(
        id=analysis.id,
        project_name=analysis.project_name,
        filename=analysis.filename,
        language=analysis.language,
        status=analysis.status.value,
        vulnerability_count=analysis.vulnerability_count,
        highest_severity=analysis.highest_severity,
        line_count=analysis.line_count,
        created_at=analysis.created_at,
        source_code=analysis.source_code,
        result=payload,
        explain_locale=analysis.explain_locale,
    )


@router.get("", response_model=List[AnalysisSummary])
def list_analyses(
    q: Optional[str] = None,
    language: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    query = db.query(Analysis).filter(Analysis.user_id == user.id)
    if language:
        query = query.filter(Analysis.language == language)
    if q:
        like = f"%{q}%"
        query = query.filter((Analysis.filename.ilike(like)) | (Analysis.project_name.ilike(like)))
    rows = query.order_by(Analysis.created_at.desc()).offset(offset).limit(min(limit, 100)).all()
    return [
        AnalysisSummary(
            id=r.id,
            project_name=r.project_name,
            filename=r.filename,
            language=r.language,
            status=r.status.value,
            vulnerability_count=r.vulnerability_count,
            highest_severity=r.highest_severity,
            line_count=r.line_count,
            created_at=r.created_at,
        )
        for r in rows
    ]


@router.get("/{analysis_id}", response_model=AnalysisDetail)
def get_analysis(analysis_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    row = db.get(Analysis, analysis_id)
    if not row or row.user_id != user.id:
        raise HTTPException(status_code=404, detail="Không tìm thấy phân tích")
    result = json.loads(row.result_json) if row.result_json else None
    return AnalysisDetail(
        id=row.id,
        project_name=row.project_name,
        filename=row.filename,
        language=row.language,
        status=row.status.value,
        vulnerability_count=row.vulnerability_count,
        highest_severity=row.highest_severity,
        line_count=row.line_count,
        created_at=row.created_at,
        source_code=row.source_code,
        result=result,
        explain_locale=row.explain_locale,
        error_message=row.error_message,
    )


@router.delete("/{analysis_id}")
def delete_analysis(analysis_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    row = db.get(Analysis, analysis_id)
    if not row or row.user_id != user.id:
        raise HTTPException(status_code=404, detail="Không tìm thấy phân tích")
    db.delete(row)
    db.commit()
    return {"ok": True}


@router.delete("")
def delete_all_analyses(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    db.query(Analysis).filter(Analysis.user_id == user.id).delete()
    db.commit()
    return {"ok": True}


@router.post("/feedback")
def post_feedback(body: FeedbackRequest, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    db.add(
        Feedback(
            user_id=user.id,
            analysis_id=body.analysis_id,
            vulnerability_id=body.vulnerability_id,
            rating=body.rating,
            comment=body.comment or "",
        )
    )
    db.commit()
    return {"ok": True}


@router.post("/{analysis_id}/vulnerabilities/{vuln_id}/false-positive")
def mark_fp(
    analysis_id: int,
    vuln_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    analysis = db.get(Analysis, analysis_id)
    if not analysis or analysis.user_id != user.id:
        raise HTTPException(status_code=404, detail="Không tìm thấy")
    v = db.get(Vulnerability, vuln_id)
    if not v or v.analysis_id != analysis_id:
        raise HTTPException(status_code=404, detail="Không tìm thấy finding")
    v.is_false_positive = True
    db.add(v)
    db.commit()
    return {"ok": True}
