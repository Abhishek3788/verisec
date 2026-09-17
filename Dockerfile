# Stage 1: Build React Frontend
FROM node:22-alpine AS frontend-builder
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend ./
RUN npm run build

# Stage 2: Python Backend Runtime
FROM python:3.11-slim
WORKDIR /app

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy backend requirements & install
COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install --no-cache-dir -r ./backend/requirements.txt

# Copy backend application code
COPY backend ./backend

# Copy built frontend static files to backend/static
COPY --from=frontend-builder /app/frontend/dist ./backend/static

# Expose FastAPI port
EXPOSE 8000

# Environment defaults
ENV PYTHONUNBUFFERED=1
ENV DATABASE_URL="sqlite:///./verisec.db"
ENV PORT=8000

WORKDIR /app/backend

# Initialize SQLite offline indexes and launch Uvicorn server
CMD python scripts/fetch_mitre_data.py && \
    python scripts/fetch_sigma_rules.py && \
    uvicorn app.main:app --host 0.0.0.0 --port 8000
