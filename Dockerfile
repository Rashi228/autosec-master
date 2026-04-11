# ============================================================
# AutoSec OpenEnv — Secure Docker Image with Full-Stack Support
# ============================================================

# --- STAGE 1: Build Frontend Dashboard ---
FROM node:20 AS frontend-build
WORKDIR /app/dashboard
# Copy dashboard package files first for caching
COPY dashboard/package*.json ./
RUN npm install
# Build the dashboard source
COPY dashboard/ ./
RUN npm run build


# --- STAGE 2: Backend + Final Image ---
FROM python:3.11-slim
LABEL maintainer="AutoSec OpenEnv Team"
LABEL description="Autonomous SOC Defensive Layer with RL & LLM support"

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

WORKDIR /app

# Install critical system utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Pre-download embedding model to prevent 429 errors at runtime
RUN python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2')"

# Copy backend components
COPY autosec_openenv/ ./autosec_openenv/
COPY backend/ ./backend/
COPY logs/ ./logs/
COPY inference.py .
COPY .env* .

# Inject the built frontend files directly from STAGE 1
COPY --from=frontend-build /app/dashboard/dist ./dashboard/dist

RUN useradd -m -u 1000 appuser && \
    chown -R appuser:appuser /app
USER appuser

EXPOSE 7860

HEALTHCHECK --interval=20s --timeout=15s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:7860/health || exit 1

CMD ["uvicorn", "backend.api.server_rl:app", "--host", "0.0.0.0", "--port", "7860", "--workers", "1"]