# ============================================================
# AutoSec OpenEnv — Secure Docker Image
# ============================================================
# Optimized for high-performance RL inference & stable simulation.
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

# Pre-install core ML/RL requirements (for Layer Caching)
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy critical project components
COPY autosec_openenv/ ./autosec_openenv/
COPY backend/ ./backend/
COPY logs/ ./logs/
COPY inference.py .
COPY .env .

# Set up dedicated non-root security user
RUN useradd -m -u 1000 appuser && \
    chown -R appuser:appuser /app
USER appuser

# Expose backend API port
EXPOSE 7860

# Hardened health check for the RL Environment
HEALTHCHECK --interval=20s --timeout=15s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:7860/health || exit 1

# Start production-grade FastAPI server with uvicorn
CMD ["uvicorn", "backend.api.server_rl:app", "--host", "0.0.0.0", "--port", "7860", "--workers", "1"]
