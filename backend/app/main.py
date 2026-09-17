import os
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app.config import settings
from app.db import init_db
from app.routers import analyze, history, health
from scripts.fetch_mitre_data import fetch_and_index_mitre
from scripts.fetch_sigma_rules import fetch_and_index_sigma

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("verisec.main")

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing VeriSec Database & Data Indexes...")
    init_db()
    try:
        fetch_and_index_mitre()
        fetch_and_index_sigma()
    except Exception as e:
        logger.warning(f"Data indexing during startup encountered notice: {e}")
    yield
    logger.info("Shutting down VeriSec Backend...")

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="LLM Hallucination Firewall for Security Teams — Real-time security claim validator.",
    lifespan=lifespan
)

# CORS Middleware setup
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount Audit Evidence Directory
if os.path.exists(settings.AUDIT_DIR):
    app.mount("/audit", StaticFiles(directory=settings.AUDIT_DIR), name="audit")

# Include Routers
app.include_router(analyze.router)
app.include_router(history.router)
app.include_router(health.router)

@app.get("/")
def root():
    return {
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "docs": "/docs",
        "health": "/api/health"
    }
