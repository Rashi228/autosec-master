# ============================================================
# AutoSec OpenEnv — Dockerfile
# ============================================================
# Designed for Hugging Face Spaces (port 7860)
# Build:  docker build -t autosec-openenv .
# Run:    docker run -p 7860:7860 autosec-openenv
# ============================================================

FROM python:3.11-slim

# Metadata
LABEL maintainer="AutoSec OpenEnv"
LABEL description="Meta OpenEnv-compliant cybersecurity incident response environment"
LABEL version="1.0.0"

# Set working directory
WORKDIR /app

# Install system deps (minimal)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY autosec_openenv/ ./autosec_openenv/
COPY api/ ./api/
COPY inference.py .

# Create non-root user (security best practice)
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

# Expose Hugging Face Spaces default port
EXPOSE 7860

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:7860/health || exit 1

# Start the FastAPI server
CMD ["uvicorn", "api.server:app", "--host", "0.0.0.0", "--port", "7860", "--workers", "1"]
