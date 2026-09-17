import httpx
from fastapi import APIRouter, Depends
from sqlmodel import Session, select, func
from app.config import settings
from app.db import get_session
from app.models.schemas import MITRETechnique, SigmaRuleIndex
from app.validation.nvd_client import nvd_cache

router = APIRouter(prefix="/api/health", tags=["health"])

@router.get("")
async def health_check(session: Session = Depends(get_session)):
    # 1. Check Groq API Key
    groq_configured = bool(settings.GROQ_API_KEY)

    # 2. Check Ollama reachability
    ollama_reachable = False
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(f"{settings.OLLAMA_BASE_URL.rstrip('/')}/api/tags")
            if resp.status_code == 200:
                ollama_reachable = True
    except Exception:
        ollama_reachable = False

    # 3. Check DB Counts
    mitre_count = session.exec(select(func.count(MITRETechnique.technique_id))).one()
    sigma_count = session.exec(select(func.count(SigmaRuleIndex.rule_id))).one()

    # 4. Optional API Keys
    abuseipdb_configured = bool(settings.ABUSEIPDB_API_KEY)
    virustotal_configured = bool(settings.VIRUSTOTAL_API_KEY)

    return {
        "status": "healthy",
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "services": {
            "groq_api": {"configured": groq_configured, "model": settings.GROQ_MODEL},
            "ollama": {"reachable": ollama_reachable, "url": settings.OLLAMA_BASE_URL, "model": settings.OLLAMA_MODEL},
            "nvd_api": {"key_configured": bool(settings.NVD_API_KEY), "cache_items": len(nvd_cache)},
            "mitre_database": {"techniques_indexed": mitre_count},
            "sigma_database": {"rules_indexed": sigma_count},
            "abuseipdb": {"configured": abuseipdb_configured},
            "virustotal": {"configured": virustotal_configured}
        }
    }
