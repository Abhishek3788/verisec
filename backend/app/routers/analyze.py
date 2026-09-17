import json
import uuid
import asyncio
import logging
from datetime import datetime
from typing import AsyncGenerator
from fastapi import APIRouter, Request, Depends
from sse_starlette.sse import EventSourceResponse
from sqlmodel import Session

from app.db import get_session
from app.models.schemas import (
    AnalyzeRequest, Claim, ClaimResult, AnalysisSummary, VerdictType, AnalysisRecord
)
from app.extraction.llm_extractor import extract_all_claims
from app.validation.nvd_client import validate_cve
from app.validation.mitre_client import validate_mitre_technique
from app.validation.sigma_client import validate_sigma_rule
from app.validation.ioc_client import validate_ioc
from app.consistency.self_consistency import evaluate_claim_consistency
from app.scoring.risk_engine import evaluate_claim

router = APIRouter(prefix="/api", tags=["analyze"])
logger = logging.getLogger("verisec.router.analyze")

async def process_single_claim(claim: Claim, context: str = None) -> ClaimResult:
    # 1. Deterministic validation according to claim type
    if claim.type == "cve":
        claimed_cvss = None
        if claim.expected_meta and "cvss" in claim.expected_meta:
            try:
                claimed_cvss = float(claim.expected_meta["cvss"])
            except Exception:
                pass
        det_val = await validate_cve(claim.value, claimed_cvss)
    elif claim.type == "mitre_technique":
        claimed_tactic = claim.expected_meta.get("tactic") if claim.expected_meta else None
        det_val = validate_mitre_technique(claim.value, claimed_tactic)
    elif claim.type == "sigma_rule":
        det_val = validate_sigma_rule(claim.value)
    elif claim.type == "ioc":
        ioc_type = claim.expected_meta.get("ioc_type") if claim.expected_meta else None
        det_val = await validate_ioc(claim.value, ioc_type)
    else:
        # Fallback for general commands or generic scores
        from app.models.schemas import ValidationDetails, ValidationStatus
        det_val = ValidationDetails(
            status=ValidationStatus.UNCHECKED,
            source="System Engine",
            message=f"Claim format recognized: {claim.value}"
        )

    # 2. Semantic consistency & Faithfulness scoring
    consistency_score, faithfulness_score = await evaluate_claim_consistency(claim, context)

    # 3. Composite Risk & Verdict calculation
    claim_result = evaluate_claim(
        claim=claim,
        det_val=det_val,
        consistency_score=consistency_score,
        faithfulness_score=faithfulness_score
    )

    return claim_result

@router.post("/analyze")
async def analyze_text(
    req: AnalyzeRequest,
    request: Request,
    stream: bool = False,
    session: Session = Depends(get_session)
):
    text = req.text.strip()
    if not text:
        return {"error": "Empty text provided"}

    # Extract claims
    claims = await extract_all_claims(text)
    analysis_id = f"analysis_{uuid.uuid4().hex[:12]}"

    if stream or "text/event-stream" in request.headers.get("accept", ""):
        async def event_generator() -> AsyncGenerator[str, None]:
            pass_cnt = 0
            flag_cnt = 0
            block_cnt = 0
            total_risk = 0.0
            results = []

            # Emit initial extraction event
            yield json.dumps({
                "event": "extraction_complete",
                "analysis_id": analysis_id,
                "total_claims_found": len(claims)
            })

            for claim in claims:
                res = await process_single_claim(claim, req.context)
                results.append(res)

                if res.verdict == VerdictType.PASS:
                    pass_cnt += 1
                elif res.verdict == VerdictType.FLAG:
                    flag_cnt += 1
                else:
                    block_cnt += 1

                total_risk += res.risk_score

                # Stream individual claim result
                yield json.dumps({
                    "event": "claim_validated",
                    "data": res.model_dump()
                })
                await asyncio.sleep(0.05)

            # Overall summary calculation
            n = len(results)
            avg_risk = round(total_risk / n, 3) if n > 0 else 0.0
            overall_verdict = VerdictType.BLOCK if block_cnt > 0 else (VerdictType.FLAG if flag_cnt > 0 else VerdictType.PASS)

            summary = AnalysisSummary(
                analysis_id=analysis_id,
                timestamp=datetime.utcnow(),
                total_claims=n,
                pass_count=pass_cnt,
                flag_count=flag_cnt,
                block_count=block_cnt,
                overall_risk_score=avg_risk,
                verdict=overall_verdict,
                claims=results
            )

            # Save in SQLite DB
            record = AnalysisRecord(
                id=analysis_id,
                timestamp=summary.timestamp,
                text_snippet=text[:200],
                total_claims=n,
                pass_count=pass_cnt,
                flag_count=flag_cnt,
                block_count=block_cnt,
                overall_risk_score=avg_risk,
                verdict=overall_verdict.value,
                report_json=summary.model_dump_json()
            )
            session.add(record)
            session.commit()

            # Emit final summary event
            yield json.dumps({
                "event": "summary",
                "data": summary.model_dump()
            })

        return EventSourceResponse(event_generator())

    # Standard JSON Response mode
    results = []
    pass_cnt = 0
    flag_cnt = 0
    block_cnt = 0
    total_risk = 0.0

    for claim in claims:
        res = await process_single_claim(claim, req.context)
        results.append(res)
        if res.verdict == VerdictType.PASS:
            pass_cnt += 1
        elif res.verdict == VerdictType.FLAG:
            flag_cnt += 1
        else:
            block_cnt += 1
        total_risk += res.risk_score

    n = len(results)
    avg_risk = round(total_risk / n, 3) if n > 0 else 0.0
    overall_verdict = VerdictType.BLOCK if block_cnt > 0 else (VerdictType.FLAG if flag_cnt > 0 else VerdictType.PASS)

    summary = AnalysisSummary(
        analysis_id=analysis_id,
        timestamp=datetime.utcnow(),
        total_claims=n,
        pass_count=pass_cnt,
        flag_count=flag_cnt,
        block_count=block_cnt,
        overall_risk_score=avg_risk,
        verdict=overall_verdict,
        claims=results
    )

    record = AnalysisRecord(
        id=analysis_id,
        timestamp=summary.timestamp,
        text_snippet=text[:200],
        total_claims=n,
        pass_count=pass_cnt,
        flag_count=flag_cnt,
        block_count=block_cnt,
        overall_risk_score=avg_risk,
        verdict=overall_verdict.value,
        report_json=summary.model_dump_json()
    )
    session.add(record)
    session.commit()

    return summary
