import os
import sys
import json
import logging
import httpx
from sqlmodel import Session, select, SQLModel

# Add backend directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.config import settings
from app.db import engine, init_db
from app.models.schemas import MITRETechnique

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("fetch_mitre")

def fetch_and_index_mitre():
    init_db()

    data_file = os.path.join(settings.DATA_DIR, "mitre_attack_enterprise.json")
    stix_data = None

    # 1. Download if not existing locally
    if not os.path.exists(data_file):
        logger.info(f"Downloading MITRE STIX bundle from {settings.MITRE_STIX_URL}...")
        try:
            with httpx.Client(timeout=30.0) as client:
                resp = client.get(settings.MITRE_STIX_URL)
                resp.raise_for_status()
                with open(data_file, "w", encoding="utf-8") as f:
                    f.write(resp.text)
                stix_data = resp.json()
                logger.info(f"Saved STIX bundle to {data_file}")
        except Exception as e:
            logger.error(f"Could not download STIX bundle ({e}). Creating basic index from local fallback.")
    else:
        logger.info(f"Loading local STIX bundle from {data_file}...")
        with open(data_file, "r", encoding="utf-8") as f:
            stix_data = json.load(f)

    count = 0
    if stix_data and "objects" in stix_data:
        objects = stix_data["objects"]
        techniques = []
        for obj in objects:
            if obj.get("type") == "attack-pattern" and not obj.get("revoked", False) and not obj.get("x_mitre_deprecated", False):
                ext_refs = obj.get("external_references", [])
                tech_id = None
                url = ""
                for ref in ext_refs:
                    if ref.get("source_name") == "mitre-attack":
                        tech_id = ref.get("external_id")
                        url = ref.get("url", "")
                        break

                if tech_id and tech_id.startswith("T"):
                    name = obj.get("name", "")
                    description = obj.get("description", "")[:500]
                    tactics_list = [phase.get("phase_name", "") for phase in obj.get("kill_chain_phases", [])]
                    tactics_str = ", ".join(t.replace("-", " ").title() for t in tactics_list if t)
                    
                    is_subtech = "." in tech_id
                    parent_id = tech_id.split(".")[0] if is_subtech else None

                    techniques.append(MITRETechnique(
                        technique_id=tech_id,
                        name=name,
                        tactic=tactics_str or "Enterprise",
                        description=description,
                        url=url,
                        is_subtechnique=is_subtech,
                        parent_id=parent_id
                    ))

        with Session(engine) as session:
            for tech in techniques:
                session.merge(tech)
            session.commit()
            count = len(techniques)

    logger.info(f"Indexed {count} MITRE ATT&CK techniques in SQLite.")

if __name__ == "__main__":
    fetch_and_index_mitre()
