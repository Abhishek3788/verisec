from datetime import datetime
from enum import Enum
from typing import Optional, List, Dict, Any
from sqlmodel import SQLModel, Field, JSON, Column

class ClaimType(str, Enum):
    CVE = "cve"
    MITRE_TECHNIQUE = "mitre_technique"
    IOC = "ioc"
    SIGMA_RULE = "sigma_rule"
    CVSS_SCORE = "cvss_score"
    COMMAND = "command"

class ValidationStatus(str, Enum):
    EXISTS = "EXISTS"
    NOT_FOUND = "NOT_FOUND"
    MISMATCH = "MISMATCH"
    UNCHECKED = "UNCHECKED"
    ERROR = "ERROR"

class VerdictType(str, Enum):
    PASS = "PASS"
    FLAG = "FLAG"
    BLOCK = "BLOCK"

# Request Schema
class AnalyzeRequest(SQLModel):
    text: str
    context: Optional[str] = None

# Single Extracted Claim
class Claim(SQLModel):
    type: ClaimType
    value: str
    raw_span: str
    context_hint: Optional[str] = None
    expected_meta: Optional[Dict[str, Any]] = None

# Validation details returned per validator
class ValidationDetails(SQLModel):
    status: ValidationStatus
    source: str
    details: Dict[str, Any] = {}
    message: Optional[str] = None

# Final Claim Result
class ClaimResult(SQLModel):
    claim: Claim
    deterministic: ValidationDetails
    consistency_score: float = 1.0
    faithfulness_score: float = 1.0
    risk_score: float = 0.0
    verdict: VerdictType
    evidence_id: str
    citations: List[str] = []

# Final Overall Analysis Summary
class AnalysisSummary(SQLModel):
    analysis_id: str
    timestamp: datetime
    total_claims: int
    pass_count: int
    flag_count: int
    block_count: int
    overall_risk_score: float
    verdict: VerdictType
    claims: List[ClaimResult] = []

# Database Models
class AnalysisRecord(SQLModel, table=True):
    __tablename__ = "analysis_records"
    
    id: str = Field(primary_key=True)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    text_snippet: str
    total_claims: int
    pass_count: int
    flag_count: int
    block_count: int
    overall_risk_score: float
    verdict: str
    report_json: str = Field(sa_column=Column(JSON))

class MITRETechnique(SQLModel, table=True):
    __tablename__ = "mitre_techniques"
    
    technique_id: str = Field(primary_key=True)  # e.g., T1059 or T1059.001
    name: str
    tactic: str
    description: str
    url: str
    is_subtechnique: bool = False
    parent_id: Optional[str] = None

class SigmaRuleIndex(SQLModel, table=True):
    __tablename__ = "sigma_rules"
    
    rule_id: str = Field(primary_key=True)  # UUID or title slug
    title: str
    status: Optional[str] = None
    logsource_category: Optional[str] = None
    logsource_product: Optional[str] = None
    file_path: str
