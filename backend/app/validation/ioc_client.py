import httpx
import logging
from typing import Dict, Any, Optional
from app.config import settings
from app.models.schemas import ValidationDetails, ValidationStatus

logger = logging.getLogger("verisec.ioc")

async def validate_ioc(ioc_value: str, ioc_type: Optional[str] = None) -> ValidationDetails:
    value = ioc_value.strip()

    # Determine type if not provided
    if not ioc_type:
        if "." in value and not value.replace(".", "").isdigit():
            ioc_type = "domain"
        elif ":" in value or (value.count(".") == 3 and value.replace(".", "").isdigit()):
            ioc_type = "ip"
        elif len(value) in (32, 64):
            ioc_type = "hash"
        else:
            ioc_type = "unknown"

    # 1. IP Check via AbuseIPDB
    if ioc_type == "ip":
        if settings.ABUSEIPDB_API_KEY:
            try:
                headers = {
                    "Key": settings.ABUSEIPDB_API_KEY,
                    "Accept": "application/json"
                }
                params = {"ipAddress": value, "maxAgeInDays": 90}
                async with httpx.AsyncClient(timeout=8.0) as client:
                    resp = await client.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params)
                    if resp.status_code == 200:
                        data = resp.json().get("data", {})
                        score = data.get("abuseConfidenceScore", 0)
                        return ValidationDetails(
                            status=ValidationStatus.EXISTS if score < 80 else ValidationStatus.MISMATCH,
                            source="AbuseIPDB",
                            message=f"IP {value} Abuse Score: {score}%.",
                            details={
                                "ip": value,
                                "abuse_score": score,
                                "country": data.get("countryCode"),
                                "isp": data.get("isp"),
                                "total_reports": data.get("totalReports")
                            }
                        )
            except Exception as e:
                logger.warning(f"AbuseIPDB request failed: {e}")

    # 2. VirusTotal Check for Hashes / Domains / IPs
    if settings.VIRUSTOTAL_API_KEY:
        try:
            headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}
            vt_endpoint = ""
            if ioc_type == "hash":
                vt_endpoint = f"https://www.virustotal.com/api/v3/files/{value}"
            elif ioc_type == "domain":
                vt_endpoint = f"https://www.virustotal.com/api/v3/domains/{value}"

            if vt_endpoint:
                async with httpx.AsyncClient(timeout=8.0) as client:
                    resp = await client.get(vt_endpoint, headers=headers)
                    if resp.status_code == 200:
                        stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                        malicious = stats.get("malicious", 0)
                        return ValidationDetails(
                            status=ValidationStatus.EXISTS,
                            source="VirusTotal",
                            message=f"VirusTotal detections: {malicious} engine(s) flagged as malicious.",
                            details={"ioc": value, "malicious_count": malicious, "stats": stats}
                        )
                    elif resp.status_code == 404:
                        return ValidationDetails(
                            status=ValidationStatus.NOT_FOUND,
                            source="VirusTotal",
                            message=f"IOC {value} not seen in VirusTotal database.",
                            details={"ioc": value, "exists": False}
                        )
        except Exception as e:
            logger.warning(f"VirusTotal request failed: {e}")

    # Fallback response when no API keys are set or APIs offline
    return ValidationDetails(
        status=ValidationStatus.UNCHECKED,
        source="IOC Reputation (No Key Configured)",
        message=f"IOC '{value}' format valid. (Optional API key for AbuseIPDB/VirusTotal not configured).",
        details={"value": value, "ioc_type": ioc_type, "checked": False}
    )
