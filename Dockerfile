# Video Generation System - Production Dockerfile
# Multi-stage build for optimized image size

# Stage 1: Frontend build stage (Node.js for Tailwind CSS)
FROM node:20-slim AS frontend-builder

WORKDIR /frontend

# Copy package files and install dependencies
COPY package.json package-lock.json* ./
RUN npm ci --only=production 2>/dev/null || npm install

# Copy Tailwind config and source files
COPY tailwind.config.js postcss.config.js ./
COPY app/static/css/src/ ./app/static/css/src/
COPY app/templates/ ./app/templates/
COPY app/static/js/ ./app/static/js/

# Build production CSS
RUN npm run build:css

# Stage 2: Python build stage
FROM python:3.12-slim AS builder

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    make \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy requirements and install Python dependencies
COPY requirements.txt /tmp/
RUN pip install --upgrade pip setuptools wheel && \
    pip install -r /tmp/requirements.txt

# Stage 3: Runtime stage
FROM python:3.12-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:$PATH" \
    ENVIRONMENT=production

# Install runtime dependencies including FFmpeg
RUN apt-get update && apt-get install -y --no-install-recommends \
    ffmpeg \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv

# Create non-root user for security
RUN useradd -m -u 1000 videogen && \
    mkdir -p /app /app/data /app/output /app/cache && \
    chown -R videogen:videogen /app

# Set working directory
WORKDIR /app

# Copy application code
COPY --chown=videogen:videogen . .

# Copy built Tailwind CSS from frontend builder
COPY --from=frontend-builder --chown=videogen:videogen /frontend/app/static/css/tailwind.min.css /app/app/static/css/tailwind.min.css

# Create necessary directories
RUN mkdir -p \
    scripts \
    video_gen \
    app \
    inputs \
    outputs \
    cache/audio \
    cache/frames \
    logs

# Switch to non-root user
USER videogen

# Expose port (Railway provides $PORT, default 8000 for local)
EXPOSE 8000

# Set default port and PYTHONPATH (Railway overrides PORT)
ENV PORT=8000
ENV PYTHONPATH=/app:/app/scripts

# Health check - using /api/health endpoint
HEALTHCHECK --interval=30s --timeout=10s --start-period=90s --retries=5 \
    CMD curl -f http://localhost:${PORT}/api/health || exit 1

# Default command - use startup script for better diagnostics
CMD ["python", "start.py"]

# Alternative commands (override with docker run):
# For CLI mode: docker run video-gen python scripts/create_video.py --help
# For batch processing: docker run video-gen python scripts/generate_all_videos_unified_v2.py
