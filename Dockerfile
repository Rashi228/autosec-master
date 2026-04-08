# ============================================================
# Stage 1: Build the Dashboard (React + Vite)
# ============================================================
FROM node:20-slim AS build-stage

WORKDIR /dashboard

# Install build dependencies
COPY dashboard/package*.json ./
RUN npm install

# Copy source and build
COPY dashboard/ ./
RUN npm run build

# ============================================================
# Stage 2: Final Production Environment (Python 3.11)
# ============================================================
FROM python:3.11-slim

# System metadata
LABEL maintainer="AutoSec OpenEnv Team"
LABEL description="Autonomous SOC Defensive Layer with RL & LLM support"

# Set non-interactive install
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

WORKDIR /app

# Install critical system utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Pre-install core ML/RL requirements
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy critical project components
COPY autosec_openenv/ ./autosec_openenv/
COPY backend/ ./backend/
COPY logs/ ./logs/
COPY chroma_db/ ./chroma_db/
COPY inference.py .
COPY .env* .

# Copy built dashboard from build-stage
COPY --from=build-stage /dashboard/dist ./dashboard/dist

# Set up dedicated non-root security user (UID 1000 for HF Space compatibility)
RUN useradd -m -u 1000 appuser && \
    mkdir -p /app/logs /app/chroma_db && \
    chown -R appuser:appuser /app
USER appuser

# Expose backend API port (7860 is default for HF Spaces)
EXPOSE 7860

# Hardened health check
HEALTHCHECK --interval=20s --timeout=15s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:7860/health || exit 1

# Start production-grade FastAPI server with uvicorn
# The app serves both the API and the static UI files from /
CMD ["uvicorn", "backend.api.server_rl:app", "--host", "0.0.0.0", "--port", "7860", "--workers", "1"]
