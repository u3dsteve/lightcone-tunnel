#!/usr/bin/env bash
# Lightcone Tunnel - Docker Image Builder
# Usage: ./build-docker.sh

set -e

IMAGE_NAME="lightcone-tunnel"
TAG="latest"

# Check Docker availability
if ! command -v docker &> /dev/null; then
    echo "[ERROR] Docker is not installed or not in PATH"
    exit 1
fi

# Check required files
if [[ ! -f "lightcone-tunnel.py" ]]; then
    echo "[ERROR] lightcone-tunnel.py not found. Run this script from the project root."
    exit 1
fi

if [[ ! -f "requirements.txt" ]]; then
    echo "[ERROR] requirements.txt not found."
    exit 1
fi

# Build the image
echo "[INFO] Building $IMAGE_NAME:$TAG ..."
docker build -t "${IMAGE_NAME}:${TAG}" .

echo "[OK] Build complete: ${IMAGE_NAME}:${TAG}"
