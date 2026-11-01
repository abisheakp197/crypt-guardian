FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential \
    g++ \
    make \
    pkg-config \
    libfuse3-dev \
    fuse3 \
    libssl-dev \
    python3 \
    python3-pip \
    python3-venv \
    curl \
    kmod \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies for test runner and mock ransomware
RUN pip install --no-cache-dir --break-system-packages cryptography

WORKDIR /r2e
COPY . /r2e

RUN make clean && make

RUN mkdir -p /mnt/r2e_backing /mnt/r2e_protected /var/log/r2e

# Provide default entrypoint script
CMD ["/bin/bash"]
