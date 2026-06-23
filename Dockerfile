FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Gitleaks
RUN GITLEAKS_VERSION=8.18.4 && \
    curl -sSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
    | tar -xz -C /usr/local/bin gitleaks && \
    chmod +x /usr/local/bin/gitleaks

# Install Python security tools
RUN pip install --no-cache-dir \
    bandit[toml]==1.7.9 \
    semgrep==1.78.0 \
    pip-audit==2.7.3 \
    jinja2==3.1.4 \
    gitpython==3.1.43 \
    requests==2.32.3

COPY pipeline.py /app/pipeline.py
COPY report_template.html /app/report_template.html

RUN mkdir -p /app/reports /tmp/repo

ENTRYPOINT ["python", "/app/pipeline.py"]
