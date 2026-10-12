FROM python:3.11-slim

# Create dedicated non-root user
RUN useradd -m -u 1000 appuser

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application directories
COPY backend/ /app/backend/
COPY data/ /app/data/
COPY artifacts/ /app/artifacts/

# Prepare persistent data directory and permissions
RUN mkdir -p /data && chown -R appuser:appuser /data /app

# Environment configuration
ENV DATABASE_URL="sqlite:////data/audit.db" \
    CORS_ORIGINS="*" \
    MODEL_DIR="/app/artifacts/models/v2" \
    DATA_DIR="/app/data/processed" \
    PYTHONPATH="/app/backend" \
    PYTHONUNBUFFERED=1

WORKDIR /app/backend
USER appuser

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
