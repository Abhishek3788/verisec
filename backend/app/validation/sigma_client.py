import logging
from typing import Optional, Dict, Any
from sqlmodel import Session, select
from app.db import engine
from app.models.schemas import SigmaRuleIndex, ValidationDetails, ValidationStatus

logger = logging.getLogger("verisec.sigma")

# Fallback collection of well-known Sigma HQ rule titles
LOCAL_SIGMA_RULES = {
    "powershell_download_cradle": {
        "title": "PowerShell Download Cradle",
        "category": "process_creation",
        "product": "windows",
        "url": "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_powershell_download_cradle.yml"
    },
    "mimikatz_execution": {
        "title": "Mimikatz Command Line Arguments",
        "category": "process_creation",
        "product": "windows",
        "url": "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_mimikatz_command_line.yml"
    },
    "suspicious_certutil_download": {
        "title": "Suspicious Certutil Command",
        "category": "process_creation",
        "product": "windows",
        "url": "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_certutil_download.yml"
    },
    "rare_service_installation": {
        "title": "Rare Service Installation",
        "category": "system",
        "product": "windows",
        "url": "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/system/win_system_service_install.yml"
    }
}

def validate_sigma_rule(rule_query: str) -> ValidationDetails:
    query = rule_query.strip().lower()

    # 1. Search SQLite DB
    try:
        with Session(engine) as session:
            statement = select(SigmaRuleIndex).where(
                SigmaRuleIndex.title.ilike(f"%{query}%")
            )
            rule = session.exec(statement).first()
            if rule:
                return ValidationDetails(
                    status=ValidationStatus.EXISTS,
                    source="SigmaHQ Rules Index",
                    message=f"Matched Sigma rule: '{rule.title}'.",
                    details={
                        "rule_id": rule.rule_id,
                        "title": rule.title,
                        "file_path": rule.file_path,
                        "exists": True
                    }
                )
    except Exception as e:
        logger.debug(f"SQLite Sigma query error: {e}")

    # 2. Search local fallback dictionary
    for k, info in LOCAL_SIGMA_RULES.items():
        if query in k or query in info["title"].lower():
            return ValidationDetails(
                status=ValidationStatus.EXISTS,
                source="SigmaHQ Local Mirror",
                message=f"Matched Sigma rule: '{info['title']}'.",
                details={
                    "title": info["title"],
                    "url": info["url"],
                    "exists": True
                }
            )

    # 3. Not found
    return ValidationDetails(
        status=ValidationStatus.NOT_FOUND,
        source="SigmaHQ",
        message=f"No matching Sigma rule found for '{rule_query}'.",
        details={"query": rule_query, "exists": False}
    )
