# syntax=docker/dockerfile:1
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# System dependencies for building Python packages and TenSEAL
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    g++ \
    git \
    curl \
    ca-certificates \
    gfortran \
    libopenblas-dev \
    libssl-dev \
  && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt
RUN pip install --upgrade pip \
 && pip install --no-cache-dir -r requirements.txt

# Copy source code and relevant assets
COPY src /app/src
COPY benchmarks /app/benchmarks
COPY README.md /app/README.md

# Prepare runtime directories (mapped via volumes in compose)
RUN mkdir -p /app/data /app/data/encrypted /app/data/keys

ENV FLASK_APP=src.api.app
ENV FLASK_RUN_HOST=0.0.0.0
EXPOSE 5000

CMD ["flask", "run", "--host=0.0.0.0", "--port=5000"]

