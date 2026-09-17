import json
import os
import hashlib
from datetime import datetime
from typing import List, Tuple, Dict, Any
from app.config import settings
from app.models.schemas import Claim, ValidationDetails, VerdictType

def generate_evidence_packet(
    claim: Claim,
    det_val: ValidationDetails,
    consistency_score: float,
    faithfulness_score: float,
    risk_score: float,
    verdict: VerdictType,
    citations: List[str]
) -> Tuple[str, str]:
    """
    Generates a cryptographically signed (SHA-256) JSON evidence packet.
    Returns (evidence_id, file_path).
    """
    timestamp_str = datetime.utcnow().isoformat() + "Z"
    
    packet_data: Dict[str, Any] = {
        "timestamp": timestamp_str,
        "verisec_version": settings.APP_VERSION,
        "claim": {
            "type": claim.type.value if hasattr(claim.type, "value") else str(claim.type),
            "value": claim.value,
            "raw_span": claim.raw_span,
            "expected_meta": claim.expected_meta
        },
        "validation": {
            "status": det_val.status.value if hasattr(det_val.status, "value") else str(det_val.status),
            "source": det_val.source,
            "message": det_val.message,
            "details": det_val.details
        },
        "scores": {
            "consistency": consistency_score,
            "faithfulness": faithfulness_score,
            "risk_score": risk_score
        },
        "verdict": verdict.value if hasattr(verdict, "value") else str(verdict),
        "citations": citations
    }

    # Canonical JSON string for hashing
    raw_json = json.dumps(packet_data, sort_keys=True)
    sha256_hash = hashlib.sha256(raw_json.encode("utf-8")).hexdigest()
    
    evidence_id = f"sha256:{sha256_hash[:16]}"
    packet_data["evidence_id"] = evidence_id
    packet_data["sha256_signature"] = sha256_hash

    # Save packet to audit directory
    filename = f"evidence_{sha256_hash[:16]}.json"
    file_path = os.path.join(settings.AUDIT_DIR, filename)
    
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(packet_data, f, indent=2)

    return evidence_id, file_path
