import json
import logging
import httpx
from typing import List, Dict, Any
from app.config import settings
from app.models.schemas import Claim, ClaimType
from app.extraction.regex_fallback import extract_claims_regex

logger = logging.getLogger("verisec.extractor")

EXTRACTION_SYSTEM_PROMPT = """You are a security claims extraction engine. 
Given a text chunk containing security analysis, log reviews, vulnerability discussions, or IR notes, extract ALL factual security claims.

Extract the following types into JSON array:
- 'cve': CVE IDs (e.g. CVE-2024-3400)
- 'mitre_technique': MITRE ATT&CK technique IDs (e.g. T1059, T1059.001)
- 'ioc': IP addresses, domain names, file hashes (MD5/SHA256)
- 'sigma_rule': Mentioned Sigma rules or rule titles
- 'cvss_score': Claimed CVSS scores associated with vulnerabilities
- 'command': Suspicious or referenced terminal / shell commands

Output MUST be a valid JSON array of objects with keys:
- "type": string (one of 'cve', 'mitre_technique', 'ioc', 'sigma_rule', 'cvss_score', 'command')
- "value": string (normalized identifier or claim value)
- "raw_span": string (exact substring as appeared in original text)
- "expected_meta": object (optional additional details like associated CVE for CVSS score, or tactic for MITRE technique)

Respond ONLY with valid raw JSON array, without markdown backticks or explanation."""

async def extract_claims_llm_groq(text: str) -> List[Claim]:
    if not settings.GROQ_API_KEY:
        raise ValueError("GROQ_API_KEY not configured")

    headers = {
        "Authorization": f"Bearer {settings.GROQ_API_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": settings.GROQ_MODEL,
        "messages": [
            {"role": "system", "content": EXTRACTION_SYSTEM_PROMPT},
            {"role": "user", "content": text}
        ],
        "temperature": 0.0,
        "response_format": {"type": "json_object"}
    }

    async with httpx.AsyncClient(timeout=15.0) as client:
        res = await client.post("https://api.groq.com/openai/v1/chat/completions", headers=headers, json=payload)
        res.raise_for_status()
        data = res.json()
        raw_resp = data["choices"][0]["message"]["content"]
        
        # Parse JSON
        parsed = json.loads(raw_resp)
        if isinstance(parsed, dict) and "claims" in parsed:
            items = parsed["claims"]
        elif isinstance(parsed, list):
            items = parsed
        else:
            items = []

        claims = []
        for item in items:
            ctype = item.get("type")
            cval = item.get("value")
            cspan = item.get("raw_span", cval)
            if ctype and cval:
                try:
                    claims.append(Claim(
                        type=ClaimType(ctype),
                        value=str(cval).strip(),
                        raw_span=str(cspan).strip(),
                        expected_meta=item.get("expected_meta")
                    ))
                except ValueError:
                    pass
        return claims

async def extract_claims_llm_ollama(text: str) -> List[Claim]:
    url = f"{settings.OLLAMA_BASE_URL.rstrip('/')}/api/chat"
    payload = {
        "model": settings.OLLAMA_MODEL,
        "messages": [
            {"role": "system", "content": EXTRACTION_SYSTEM_PROMPT},
            {"role": "user", "content": text}
        ],
        "stream": False,
        "format": "json"
    }
    async with httpx.AsyncClient(timeout=20.0) as client:
        res = await client.post(url, json=payload)
        res.raise_for_status()
        data = res.json()
        raw_resp = data.get("message", {}).get("content", "")
        parsed = json.loads(raw_resp)
        if isinstance(parsed, dict) and "claims" in parsed:
            items = parsed["claims"]
        elif isinstance(parsed, list):
            items = parsed
        else:
            items = []

        claims = []
        for item in items:
            ctype = item.get("type")
            cval = item.get("value")
            cspan = item.get("raw_span", cval)
            if ctype and cval:
                try:
                    claims.append(Claim(
                        type=ClaimType(ctype),
                        value=str(cval).strip(),
                        raw_span=str(cspan).strip(),
                        expected_meta=item.get("expected_meta")
                    ))
                except ValueError:
                    pass
        return claims

async def extract_all_claims(text: str) -> List[Claim]:
    """Extract claims using LLM (Groq -> Ollama fallback) + merge with Regex fallback."""
    llm_claims: List[Claim] = []
    
    # 1. Try Groq
    if settings.GROQ_API_KEY:
        try:
            llm_claims = await extract_claims_llm_groq(text)
            logger.info(f"Groq extracted {len(llm_claims)} claims.")
        except Exception as e:
            logger.warning(f"Groq claim extraction failed ({e}). Trying Ollama fallback...")

    # 2. Try Ollama if Groq failed or not configured
    if not llm_claims:
        try:
            llm_claims = await extract_claims_llm_ollama(text)
            logger.info(f"Ollama extracted {len(llm_claims)} claims.")
        except Exception as e:
            logger.info(f"Ollama extraction unavailable ({e}). Using deterministic regex extraction.")

    # 3. Always run Regex extraction for deterministic baseline
    regex_claims = extract_claims_regex(text)

    # 4. Merge & deduplicate
    final_claims: List[Claim] = list(llm_claims)
    seen_keys = {(c.type, c.value.upper()) for c in llm_claims}

    for rc in regex_claims:
        key = (rc.type, rc.value.upper())
        if key not in seen_keys:
            seen_keys.add(key)
            final_claims.append(rc)

    return final_claims
