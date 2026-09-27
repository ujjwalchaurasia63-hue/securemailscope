# SecureMailScope Docker Container
# Baseline: Python 3.11 with system TShark

FROM python:3.11-slim

# Prevent interactive prompts during apt install
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Install system dependencies including TShark and curl for healthcheck
RUN echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        tshark \
        curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies first for caching efficiency
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code and data assets
COPY app/ ./app/
COPY main.py .
COPY data/ ./data/

# Expose standard Streamlit port
EXPOSE 8501

# Container healthcheck verifying Streamlit status
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl --fail http://localhost:8501/_stcore/health || exit 1

# Default command: launch interactive Streamlit interface
CMD ["python", "-m", "streamlit", "run", "main.py", "--server.port=8501", "--server.address=0.0.0.0", "--server.headless=true"]
