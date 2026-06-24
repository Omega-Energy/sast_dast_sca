FROM python:3.12-slim

LABEL maintainer="Omega-Energy Security <security@omega-energy.ru>"
LABEL description="Source code scanner: Bandit + Semgrep + Gitleaks + pip-audit"

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Gitleaks
ARG GITLEAKS_VERSION=8.18.4
RUN curl -sSfL https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_amd64.tar.gz \
    | tar -xz -C /usr/local/bin gitleaks

# Python security tools
RUN pip install --no-cache-dir \
    bandit[toml]==1.7.9 \
    semgrep==1.78.0 \
    pip-audit==2.7.3

# Custom Semgrep rules
COPY rules/ /opt/rules/

# Entrypoint script
COPY scan.py /app/scan.py

WORKDIR /app
USER nobody

ENTRYPOINT ["python", "/app/scan.py"]
