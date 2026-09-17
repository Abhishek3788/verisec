import httpx
import logging
from cachetools import TTLCache
from typing import Dict, Any, Optional
from app.config import settings
from app.models.schemas import ValidationDetails, ValidationStatus

logger = logging.getLogger("verisec.nvd")

# Cache NVD lookups for 24 hours (86400s)
nvd_cache = TTLCache(maxsize=2000, ttl=86400)

# Offline/local cache of known CVEs for instant response & testing
KNOWN_LOCAL_CVES = {
    "CVE-2024-3400": {
        "exists": True,
        "cvss": 10.0,
        "description": "Palo Alto Networks PAN-OS command injection vulnerability in GlobalProtect gateway.",
        "published": "2024-04-12",
        "severity": "CRITICAL"
    },
    "CVE-2023-34362": {
        "exists": True,
        "cvss": 9.8,
        "description": "PROGRESS MOVEit Transfer SQL Injection Vulnerability.",
        "published": "2023-05-31",
        "severity": "CRITICAL"
    },
    "CVE-2021-44228": {
        "exists": True,
        "cvss": 10.0,
        "description": "Apache Log4j2 Remote Code Execution Vulnerability (Log4Shell).",
        "published": "2021-12-10",
        "severity": "CRITICAL"
    },
    "CVE-2023-23397": {
        "exists": True,
        "cvss": 9.8,
        "description": "Microsoft Outlook Elevation of Privilege Vulnerability.",
        "published": "2023-03-14",
        "severity": "CRITICAL"
    },
    "CVE-2020-0601": {
        "exists": True,
        "cvss": 8.1,
        "description": "Windows CryptoAPI Spoofing Vulnerability (CurveBall).",
        "published": "2020-01-14",
        "severity": "HIGH"
    },
    "CVE-2017-0144": {
        "exists": True,
        "cvss": 8.1,
        "description": "Windows SMB Remote Code Execution Vulnerability (EternalBlue).",
        "published": "2017-03-14",
        "severity": "HIGH"
    },
}

async def validate_cve(cve_id: str, claimed_cvss: Optional[float] = None) -> ValidationDetails:
    cve_id = cve_id.strip().upper()

    # 1. Check in-memory cache
    if cve_id in nvd_cache:
        cached = nvd_cache[cve_id]
        return _build_cve_response(cve_id, cached, claimed_cvss)

    # 2. Check local fallback database
    if cve_id in KNOWN_LOCAL_CVES:
        data = KNOWN_LOCAL_CVES[cve_id]
        nvd_cache[cve_id] = data
        return _build_cve_response(cve_id, data, claimed_cvss)

    # 3. Query NVD REST API
    headers = {}
    if settings.NVD_API_KEY:
        headers["apiKey"] = settings.NVD_API_KEY

    params = {"cveId": cve_id}

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(settings.NVD_API_URL, params=params, headers=headers)
            if resp.status_code == 200:
                res_data = resp.json()
                vulnerabilities = res_data.get("vulnerabilities", [])
                if vulnerabilities:
                    vuln = vulnerabilities[0].get("cve", {})
                    metrics = vuln.get("metrics", {})

                    cvss_val = None
                    if "cvssMetricV31" in metrics:
                        cvss_val = metrics["cvssMetricV31"][0]["cvssData"].get("baseScore")
                    elif "cvssMetricV30" in metrics:
                        cvss_val = metrics["cvssMetricV30"][0]["cvssData"].get("baseScore")
                    elif "cvssMetricV2" in metrics:
                        cvss_val = metrics["cvssMetricV2"][0]["cvssData"].get("baseScore")

                    descriptions = vuln.get("descriptions", [])
                    desc = descriptions[0].get("value") if descriptions else "No description available."
                    published = vuln.get("published", "")[:10]

                    cve_info = {
                        "exists": True,
                        "cvss": cvss_val,
                        "description": desc,
                        "published": published
                    }
                    nvd_cache[cve_id] = cve_info
                    return _build_cve_response(cve_id, cve_info, claimed_cvss)
                else:
                    # CVE does not exist in NVD database
                    cve_info = {"exists": False}
                    nvd_cache[cve_id] = cve_info
                    return ValidationDetails(
                        status=ValidationStatus.NOT_FOUND,
                        source="NVD",
                        message=f"{cve_id} was NOT found in the official NVD database.",
                        details={"cve_id": cve_id, "exists": False}
                    )
            elif resp.status_code == 404:
                cve_info = {"exists": False}
                nvd_cache[cve_id] = cve_info
                return ValidationDetails(
                    status=ValidationStatus.NOT_FOUND,
                    source="NVD",
                    message=f"{cve_id} does not exist in NVD.",
                    details={"cve_id": cve_id, "exists": False}
                )
            else:
                logger.warning(f"NVD API returned status {resp.status_code} for {cve_id}")
    except Exception as e:
        logger.warning(f"NVD API call failed for {cve_id}: {e}")

    # Fallback heuristic: If CVE ID has a future year (e.g., CVE-2099-xxxx), it's definitely fabricated
    try:
        parts = cve_id.split("-")
        year = int(parts[1])
        if year > 2026:
            return ValidationDetails(
                status=ValidationStatus.NOT_FOUND,
                source="NVD (Heuristic)",
                message=f"{cve_id} contains a invalid or future year ({year}). Fabricated CVE.",
                details={"cve_id": cve_id, "exists": False, "reason": "invalid_year"}
            )
    except Exception:
        pass

    return ValidationDetails(
        status=ValidationStatus.UNCHECKED,
        source="NVD",
        message=f"Could not verify {cve_id} due to network timeout or rate limit.",
        details={"cve_id": cve_id}
    )

def _build_cve_response(cve_id: str, data: Dict[str, Any], claimed_cvss: Optional[float]) -> ValidationDetails:
    if not data.get("exists", False):
        return ValidationDetails(
            status=ValidationStatus.NOT_FOUND,
            source="NVD",
            message=f"{cve_id} does not exist in NVD.",
            details={"cve_id": cve_id, "exists": False}
        )

    actual_cvss = data.get("cvss")
    status = ValidationStatus.EXISTS
    msg = f"{cve_id} exists in NVD."

    if claimed_cvss is not None and actual_cvss is not None:
        if abs(claimed_cvss - actual_cvss) > 0.5:
            status = ValidationStatus.MISMATCH
            msg = f"{cve_id} exists, but claimed CVSS ({claimed_cvss}) mismatches official NVD CVSS ({actual_cvss})."

    return ValidationDetails(
        status=status,
        source="NVD",
        message=msg,
        details={
            "cve_id": cve_id,
            "exists": True,
            "cvss": actual_cvss,
            "claimed_cvss": claimed_cvss,
            "published": data.get("published"),
            "description": data.get("description")
        }
    )
