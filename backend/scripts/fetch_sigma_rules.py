import os
import sys
import logging
from sqlmodel import Session

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.db import engine, init_db
from app.models.schemas import SigmaRuleIndex

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("fetch_sigma")

DEFAULT_SIGMA_RULES = [
    SigmaRuleIndex(
        rule_id="proc_creation_win_powershell_download_cradle",
        title="PowerShell Download Cradle",
        status="stable",
        logsource_category="process_creation",
        logsource_product="windows",
        file_path="rules/windows/process_creation/proc_creation_win_powershell_download_cradle.yml"
    ),
    SigmaRuleIndex(
        rule_id="proc_creation_win_mimikatz_command_line",
        title="Mimikatz Command Line Arguments",
        status="stable",
        logsource_category="process_creation",
        logsource_product="windows",
        file_path="rules/windows/process_creation/proc_creation_win_mimikatz_command_line.yml"
    ),
    SigmaRuleIndex(
        rule_id="proc_creation_win_certutil_download",
        title="Suspicious Certutil Command",
        status="stable",
        logsource_category="process_creation",
        logsource_product="windows",
        file_path="rules/windows/process_creation/proc_creation_win_certutil_download.yml"
    ),
    SigmaRuleIndex(
        rule_id="win_system_service_install",
        title="Rare Service Installation",
        status="stable",
        logsource_category="system",
        logsource_product="windows",
        file_path="rules/windows/builtin/system/win_system_service_install.yml"
    ),
    SigmaRuleIndex(
        rule_id="proc_creation_win_vssadmin_shadows_deletion",
        title="Volume Shadow Copy Deletion via Vssadmin",
        status="stable",
        logsource_category="process_creation",
        logsource_product="windows",
        file_path="rules/windows/process_creation/proc_creation_win_vssadmin_shadows_deletion.yml"
    )
]

def fetch_and_index_sigma():
    init_db()
    with Session(engine) as session:
        for rule in DEFAULT_SIGMA_RULES:
            session.merge(rule)
        session.commit()
    logger.info(f"Indexed {len(DEFAULT_SIGMA_RULES)} Sigma HQ rules in SQLite.")

if __name__ == "__main__":
    fetch_and_index_sigma()
