FROM python:3.12-slim

LABEL maintainer="Omega-Energy Security <security@omega-energy.ru>"
LABEL description="ClamAV scanner: antivirus/malware detection for project files"

# Install ClamAV
RUN apt-get update && apt-get install -y --no-install-recommends \
    clamav \
    clamav-daemon \
    clamav-freshclam \
    && rm -rf /var/lib/apt/lists/*

# Update virus definitions
RUN freshclam || true

# Python client for clamd
RUN pip install --no-cache-dir pyclamd==0.4.0

# Entrypoint
COPY scan_clamav.py /app/scan_clamav.py

WORKDIR /app

ENTRYPOINT ["python", "/app/scan_clamav.py"]
