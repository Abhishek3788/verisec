import pytest
import asyncio
from app.extraction.regex_fallback import extract_claims_regex
from app.validation.nvd_client import validate_cve
from app.validation.mitre_client import validate_mitre_technique
from app.validation.sigma_client import validate_sigma_rule
from app.models.schemas import ValidationStatus, ClaimType

def test_regex_extraction():
    sample = "Analyst notes: Detected activity mapping to T1059.001 using CVE-2024-3400 with CVSS score 10.0. Also saw fake CVE-2099-99999."
    claims = extract_claims_regex(sample)
    
    types_found = {c.type for c in claims}
    vals_found = {c.value for c in claims}

    assert ClaimType.CVE in types_found
    assert ClaimType.MITRE_TECHNIQUE in types_found
    assert "CVE-2024-3400" in vals_found
    assert "CVE-2099-99999" in vals_found
    assert "T1059.001" in vals_found

@pytest.mark.asyncio
async def test_cve_validation():
    # Real CVE
    res_real = await validate_cve("CVE-2024-3400")
    assert res_real.status == ValidationStatus.EXISTS
    assert res_real.details["exists"] is True

    # Fabricated CVE
    res_fake = await validate_cve("CVE-2099-99999")
    assert res_fake.status == ValidationStatus.NOT_FOUND
    assert res_fake.details["exists"] is False

def test_mitre_validation():
    # Real technique
    res_real = validate_mitre_technique("T1059.001")
    assert res_real.status == ValidationStatus.EXISTS
    assert res_real.details["name"] == "PowerShell"

    # Fake technique
    res_fake = validate_mitre_technique("T9999.999")
    assert res_fake.status == ValidationStatus.NOT_FOUND

def test_sigma_validation():
    res_real = validate_sigma_rule("PowerShell Download Cradle")
    assert res_real.status == ValidationStatus.EXISTS

    res_fake = validate_sigma_rule("NonExistentFakeRule12345")
    assert res_fake.status == ValidationStatus.NOT_FOUND
