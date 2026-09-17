import json
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select, desc
from app.db import get_session
from app.models.schemas import AnalysisRecord

router = APIRouter(prefix="/api/history", tags=["history"])

@router.get("")
def list_history(
    limit: int = 20,
    offset: int = 0,
    session: Session = Depends(get_session)
):
    statement = select(AnalysisRecord).order_by(desc(AnalysisRecord.timestamp)).offset(offset).limit(limit)
    records = session.exec(statement).all()
    
    formatted = []
    for r in records:
        formatted.append({
            "id": r.id,
            "timestamp": r.timestamp.isoformat(),
            "text_snippet": r.text_snippet,
            "total_claims": r.total_claims,
            "pass_count": r.pass_count,
            "flag_count": r.flag_count,
            "block_count": r.block_count,
            "overall_risk_score": r.overall_risk_score,
            "verdict": r.verdict
        })
    return formatted

@router.get("/{analysis_id}")
def get_history_detail(
    analysis_id: str,
    session: Session = Depends(get_session)
):
    record = session.get(AnalysisRecord, analysis_id)
    if not record:
        raise HTTPException(status_code=404, detail="Analysis record not found")
    return json.loads(record.report_json)

@router.delete("/{analysis_id}")
def delete_history_detail(
    analysis_id: str,
    session: Session = Depends(get_session)
):
    record = session.get(AnalysisRecord, analysis_id)
    if not record:
        raise HTTPException(status_code=404, detail="Record not found")
    session.delete(record)
    session.commit()
    return {"status": "deleted", "id": analysis_id}
