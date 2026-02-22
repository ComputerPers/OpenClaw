#!/usr/bin/env bash
set -euo pipefail

# Build custom OpenClaw image with Python support
# This pre-installs Python and pip3 to speed up container startup

IMAGE_NAME="${1:-openclaw-python:latest}"
DOCKERFILE="Dockerfile.openclaw-python"

echo "Building custom OpenClaw image with Python support..."
echo "Image name: $IMAGE_NAME"
echo

# Build the image
docker build -f "$DOCKERFILE" -t "$IMAGE_NAME" .

echo
echo "✓ Image built successfully: $IMAGE_NAME"
echo
echo "To use this image, update your .env file:"
echo "  OPENCLAW_IMAGE=$IMAGE_NAME"
echo
echo "Then run:"
echo "  ./install-openclaw.sh install"
