FROM python:3.12-slim

LABEL maintainer="Omega-Energy Security <security@omega-energy.ru>"
LABEL description="SBOM generator: Syft + CycloneDX + Grype vulnerability matching"

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Syft (SBOM generation)
ARG SYFT_VERSION=1.4.1
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin v${SYFT_VERSION}

# Install Grype (vulnerability scanning)
ARG GRYPE_VERSION=0.79.1
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin v${GRYPE_VERSION}

# Python tools for CycloneDX format
RUN pip install --no-cache-dir \
    cyclonedx-bom==4.4.3

# Entrypoint
COPY generate_sbom.py /app/generate_sbom.py

WORKDIR /app
USER nobody

ENTRYPOINT ["python", "/app/generate_sbom.py"]
