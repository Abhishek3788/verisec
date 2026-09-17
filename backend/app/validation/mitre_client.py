import logging
from typing import Optional, Dict, Any
from sqlmodel import Session, select
from app.db import engine
from app.models.schemas import MITRETechnique, ValidationDetails, ValidationStatus

logger = logging.getLogger("verisec.mitre")

# Fallback dataset of popular MITRE techniques for offline/instant execution
LOCAL_MITRE_DATA = {
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution", "url": "https://attack.mitre.org/techniques/T1059/"},
    "T1059.001": {"name": "PowerShell", "tactic": "Execution", "url": "https://attack.mitre.org/techniques/T1059/001/"},
    "T1059.003": {"name": "Windows Command Shell", "tactic": "Execution", "url": "https://attack.mitre.org/techniques/T1059/003/"},
    "T1566": {"name": "Phishing", "tactic": "Initial Access", "url": "https://attack.mitre.org/techniques/T1566/"},
    "T1566.001": {"name": "Spearphishing Attachment", "tactic": "Initial Access", "url": "https://attack.mitre.org/techniques/T1566/001/"},
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "Initial Access", "url": "https://attack.mitre.org/techniques/T1190/"},
    "T1078": {"name": "Valid Accounts", "tactic": "Defense Evasion, Persistence, PrivEsc", "url": "https://attack.mitre.org/techniques/T1078/"},
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "Impact", "url": "https://attack.mitre.org/techniques/T1486/"},
    "T1003": {"name": "OS Credential Dumping", "tactic": "Credential Access", "url": "https://attack.mitre.org/techniques/T1003/"},
    "T1003.001": {"name": "LSASS Memory", "tactic": "Credential Access", "url": "https://attack.mitre.org/techniques/T1003/001/"},
    "T1021": {"name": "Remote Services", "tactic": "Lateral Movement", "url": "https://attack.mitre.org/techniques/T1021/"},
    "T1021.001": {"name": "Remote Desktop Protocol", "tactic": "Lateral Movement", "url": "https://attack.mitre.org/techniques/T1021/001/"},
    "T1055": {"name": "Process Injection", "tactic": "Defense Evasion, Privilege Escalation", "url": "https://attack.mitre.org/techniques/T1055/"},
    "T1070": {"name": "Indicator Removal", "tactic": "Defense Evasion", "url": "https://attack.mitre.org/techniques/T1070/"},
    "T1027": {"name": "Obfuscated Files or Information", "tactic": "Defense Evasion", "url": "https://attack.mitre.org/techniques/T1027/"},
    "T1548": {"name": "Abuse Elevation Control Mechanism", "tactic": "Privilege Escalation, Defense Evasion", "url": "https://attack.mitre.org/techniques/T1548/"},
}

def validate_mitre_technique(technique_id: str, claimed_tactic: Optional[str] = None) -> ValidationDetails:
    tech_id = technique_id.strip().upper()

    # 1. Query SQLite DB first
    try:
        with Session(engine) as session:
            statement = select(MITRETechnique).where(MITRETechnique.technique_id == tech_id)
            record = session.exec(statement).first()
            if record:
                return _build_mitre_response(tech_id, record.name, record.tactic, record.url, claimed_tactic)
    except Exception as e:
        logger.debug(f"SQLite MITRE query failed ({e}). Falling back to local dictionary.")

    # 2. Check local fallback dictionary
    if tech_id in LOCAL_MITRE_DATA:
        info = LOCAL_MITRE_DATA[tech_id]
        return _build_mitre_response(tech_id, info["name"], info["tactic"], info["url"], claimed_tactic)

    # 3. Not found -> Fabricated or invalid technique ID
    return ValidationDetails(
        status=ValidationStatus.NOT_FOUND,
        source="MITRE ATT&CK Enterprise",
        message=f"{tech_id} is NOT a valid MITRE ATT&CK technique ID.",
        details={"technique_id": tech_id, "exists": False}
    )

def _build_mitre_response(tech_id: str, name: str, tactic: str, url: str, claimed_tactic: Optional[str]) -> ValidationDetails:
    status = ValidationStatus.EXISTS
    msg = f"Valid MITRE ATT&CK technique: {tech_id} ({name})."

    if claimed_tactic and claimed_tactic.lower() not in tactic.lower():
        status = ValidationStatus.MISMATCH
        msg = f"{tech_id} ({name}) exists, but claimed tactic '{claimed_tactic}' does not match official tactic '{tactic}'."

    return ValidationDetails(
        status=status,
        source="MITRE ATT&CK Enterprise",
        message=msg,
        details={
            "technique_id": tech_id,
            "name": name,
            "tactic": tactic,
            "url": url,
            "exists": True
        }
    )
