FROM python:3.12-slim

LABEL maintainer="Omega-Energy Security <security@omega-energy.ru>"
LABEL description="Binary static scanner: YARA + strings + entropy analysis"

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    file \
    binutils \
    && rm -rf /var/lib/apt/lists/*

# YARA and Python tools
RUN pip install --no-cache-dir \
    yara-python==4.5.1 \
    pefile==2023.2.7

# YARA rules directory
COPY rules/ /opt/yara-rules/

# Entrypoint
COPY scan_binary.py /app/scan_binary.py

WORKDIR /app
USER nobody

ENTRYPOINT ["python", "/app/scan_binary.py"]
