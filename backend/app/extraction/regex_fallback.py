import re
from typing import List
from app.models.schemas import Claim, ClaimType

# Regular Expressions
CVE_PATTERN = re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE)
MITRE_TECHNIQUE_PATTERN = re.compile(r'\bT\d{4}(?:\.\d{3})?\b')
IPV4_PATTERN = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
MD5_PATTERN = re.compile(r'\b[a-fA-F0-9]{32}\b')
SHA256_PATTERN = re.compile(r'\b[a-fA-F0-9]{64}\b')
CVSS_PATTERN = re.compile(r'(?:CVSS[:\s]*v?[23]?\.\d?[:\s]*|CVSS\s+score[:\s]*|CVSS[:\s]+)(\d{1,2}\.\d)', re.IGNORECASE)
SIGMA_TITLE_PATTERN = re.compile(r'(?:sigma rule|rule title|sigma)[:\s]+["\']?([^"\'\n\r,]+)["\']?', re.IGNORECASE)

def extract_claims_regex(text: str) -> List[Claim]:
    claims: List[Claim] = []
    seen = set()

    # 1. CVEs
    for match in CVE_PATTERN.finditer(text):
        cve_id = match.group(0).upper()
        key = (ClaimType.CVE, cve_id)
        if key not in seen:
            seen.add(key)
            claims.append(Claim(
                type=ClaimType.CVE,
                value=cve_id,
                raw_span=match.group(0)
            ))

    # 2. MITRE Techniques
    for match in MITRE_TECHNIQUE_PATTERN.finditer(text):
        tech_id = match.group(0).upper()
        key = (ClaimType.MITRE_TECHNIQUE, tech_id)
        if key not in seen:
            seen.add(key)
            claims.append(Claim(
                type=ClaimType.MITRE_TECHNIQUE,
                value=tech_id,
                raw_span=match.group(0)
            ))

    # 3. IOCs (IPv4, MD5, SHA256)
    for match in IPV4_PATTERN.finditer(text):
        ip = match.group(0)
        # Exclude local/private ranges or versions like 127.0.0.1 or 0.0.0.0 if desired, but keep for completeness
        key = (ClaimType.IOC, ip)
        if key not in seen:
            seen.add(key)
            claims.append(Claim(
                type=ClaimType.IOC,
                value=ip,
                raw_span=match.group(0),
                expected_meta={"ioc_type": "ip"}
            ))

    for match in SHA256_PATTERN.finditer(text):
        h = match.group(0).lower()
        key = (ClaimType.IOC, h)
        if key not in seen:
            seen.add(key)
            claims.append(Claim(
                type=ClaimType.IOC,
                value=h,
                raw_span=match.group(0),
                expected_meta={"ioc_type": "sha256"}
            ))

    # 4. CVSS Scores
    for match in CVSS_PATTERN.finditer(text):
        score_val = match.group(1)
        key = (ClaimType.CVSS_SCORE, score_val)
        if key not in seen:
            seen.add(key)
            claims.append(Claim(
                type=ClaimType.CVSS_SCORE,
                value=score_val,
                raw_span=match.group(0)
            ))

    # 5. Sigma Rules
    for match in SIGMA_TITLE_PATTERN.finditer(text):
        title = match.group(1).strip()
        key = (ClaimType.SIGMA_RULE, title)
        if key not in seen and len(title) > 3:
            seen.add(key)
            claims.append(Claim(
                type=ClaimType.SIGMA_RULE,
                value=title,
                raw_span=match.group(0)
            ))

    return claims
