import uuid
from typing import List
from app.models.schemas import (
    Claim, ValidationDetails, ValidationStatus, ClaimResult, VerdictType
)
from app.audit.evidence_packet import generate_evidence_packet

def evaluate_claim(
    claim: Claim,
    det_val: ValidationDetails,
    consistency_score: float = 1.0,
    faithfulness_score: float = 1.0
) -> ClaimResult:

    # Map deterministic validation status to numerical confidence [0.0 - 1.0]
    if det_val.status == ValidationStatus.EXISTS:
        det_score = 1.0
    elif det_val.status == ValidationStatus.MISMATCH:
        det_score = 0.4
    elif det_val.status == ValidationStatus.UNCHECKED:
        det_score = 0.7
    elif det_val.status == ValidationStatus.NOT_FOUND:
        det_score = 0.0
    else:  # ERROR
        det_score = 0.3

    # Composite confidence score
    confidence = (0.60 * det_score) + (0.25 * consistency_score) + (0.15 * faithfulness_score)
    risk_score = round(1.0 - confidence, 3)

    # Determine Verdict
    if det_val.status == ValidationStatus.NOT_FOUND or risk_score >= 0.50:
        verdict = VerdictType.BLOCK
    elif det_val.status in (ValidationStatus.MISMATCH, ValidationStatus.UNCHECKED) or (0.25 <= risk_score < 0.50):
        verdict = VerdictType.FLAG
    else:
        verdict = VerdictType.PASS

    # Citations
    citations: List[str] = []
    if claim.type == "cve":
        citations.append(f"https://nvd.nist.gov/vuln/detail/{claim.value}")
    elif claim.type == "mitre_technique":
        clean_id = claim.value.replace(".", "/")
        citations.append(f"https://attack.mitre.org/techniques/{clean_id}/")
    elif claim.type == "sigma_rule":
        citations.append("https://github.com/SigmaHQ/sigma")

    # Generate Audit Evidence Packet
    evidence_id, evidence_path = generate_evidence_packet(
        claim=claim,
        det_val=det_val,
        consistency_score=consistency_score,
        faithfulness_score=faithfulness_score,
        risk_score=risk_score,
        verdict=verdict,
        citations=citations
    )

    return ClaimResult(
        claim=claim,
        deterministic=det_val,
        consistency_score=round(consistency_score, 3),
        faithfulness_score=round(faithfulness_score, 3),
        risk_score=risk_score,
        verdict=verdict,
        evidence_id=evidence_id,
        citations=citations
    )
