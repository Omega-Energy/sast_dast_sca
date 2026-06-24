FROM python:3.12-slim

LABEL maintainer="Omega-Energy Security <security@omega-energy.ru>"
LABEL description="Unpacker/deobfuscator: UPX, archives, base64, XOR, PE rebuilder"

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    upx-ucl \
    unzip \
    p7zip-full \
    binutils \
    file \
    && rm -rf /var/lib/apt/lists/*

# Python tools
RUN pip install --no-cache-dir \
    pefile==2023.2.7 \
    uncompyle6==3.9.1 \
    decompyle3==3.9.1

# Entrypoint
COPY unpack.py /app/unpack.py

WORKDIR /app
USER nobody

ENTRYPOINT ["python", "/app/unpack.py"]
