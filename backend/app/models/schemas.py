from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Language(str, Enum):
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    JAVA = "java"
    C = "c"
    CPP = "cpp"
    CSHARP = "csharp"
    PHP = "php"
    AUTO = "auto"


class ScanRequest(BaseModel):
    code: str = Field(..., min_length=1, description="Source code to scan")
    language: Language = Language.AUTO
    filename: Optional[str] = None
    include_explanations: bool = True
    include_fixes: bool = True


class BatchScanRequest(BaseModel):
    files: List[ScanRequest]


class Vulnerability(BaseModel):
    id: str
    rule_id: str
    title: str
    severity: Severity
    cwe: str
    owasp: str
    language: str
    file: Optional[str] = None
    start_line: int
    end_line: int
    start_col: int = 0
    end_col: int = 0
    snippet: str
    message: str
    confidence: float = Field(ge=0.0, le=1.0, default=0.85)
    detector: str = "rule"  # rule | hybrid | ml-discovery


class Explanation(BaseModel):
    vulnerability_id: str
    summary: str
    why_vulnerable: str
    impact: str
    attack_scenario: str
    references: List[str] = []
    secure_coding_tips: List[str] = []


class FixSuggestion(BaseModel):
    vulnerability_id: str
    strategy: str
    description: str
    fixed_code: str
    diff: str
    confidence: float = Field(ge=0.0, le=1.0, default=0.8)


class ScanResult(BaseModel):
    scan_id: str
    language: str
    filename: Optional[str]
    vulnerability_count: int
    severity_counts: Dict[str, int]
    vulnerabilities: List[Vulnerability]
    explanations: List[Explanation] = []
    fixes: List[FixSuggestion] = []
    meta: Dict[str, Any] = {}
    # Full file source for UI highlight / apply-fix (repo scans)
    source_code: Optional[str] = None


class ExplainRequest(BaseModel):
    code: str
    vulnerability: Vulnerability
    language: Language = Language.AUTO


class FixRequest(BaseModel):
    code: str
    vulnerability: Vulnerability
    language: Language = Language.AUTO


class HealthResponse(BaseModel):
    status: str
    version: str
    llm_provider: str
    supported_languages: List[str]


class ApplyFixRequest(BaseModel):
    code: str
    fixed_snippet: str
    start_line: int
    end_line: int


class ApplyFixResponse(BaseModel):
    code: str


class RepoScanRequest(BaseModel):
    github_url: Optional[str] = None
    include_explanations: bool = True
    include_fixes: bool = True
    max_files: int = Field(default=300, ge=1, le=800)
    ml_discovery: bool = False  # keep off by default (noise); product uses hybrid FP filter
    max_enrich: int = Field(default=80, ge=0, le=200, description="Max findings to explain+fix in one repo scan")


class RepoScanResult(BaseModel):
    scan_id: str
    source: str
    file_count: int
    scanned_files: int
    vulnerability_count: int
    severity_counts: Dict[str, int]
    results: List[ScanResult]
    meta: Dict[str, Any] = {}
