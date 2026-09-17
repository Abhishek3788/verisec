import os
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    APP_NAME: str = "VeriSec"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    
    # LLM Settings
    GROQ_API_KEY: Optional[str] = None
    GROQ_MODEL: str = "llama-3.3-70b-versatile"
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "llama3.1:8b"
    
    # Validation APIs
    NVD_API_KEY: Optional[str] = None
    NVD_API_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    ABUSEIPDB_API_KEY: Optional[str] = None
    VIRUSTOTAL_API_KEY: Optional[str] = None
    
    # Database & Storage
    DATABASE_URL: str = "sqlite:///./verisec.db"
    DATA_DIR: str = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
    AUDIT_DIR: str = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "audit")
    MITRE_STIX_URL: str = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    SIGMA_REPO_URL: str = "https://github.com/SigmaHQ/sigma.git"

settings = Settings()

# Ensure directories exist
os.makedirs(settings.DATA_DIR, exist_ok=True)
os.makedirs(settings.AUDIT_DIR, exist_ok=True)
