# syntax=docker/dockerfile:1
# ==============================================================================
# PS-26149: Integrated Secure Data Erasure & Advanced File Recovery Tool
# SIH 2026 - NTRO (National Technical Research Organisation)
# ==============================================================================

FROM rust:1.80-slim-bookworm AS base

LABEL maintainer="PS-26149 Team - SIH 2026"
LABEL description="Secure Data Erasure & Digital Forensics Tool"

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    pkg-config \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy cargo configuration and sources
COPY ps149/Cargo.toml ps149/Cargo.lock ./
COPY ps149/src ./src

# Copy entrypoint script
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

# Environment settings
ENV CARGO_TERM_COLOR=always

ENTRYPOINT ["/docker-entrypoint.sh"]
