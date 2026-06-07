#!/usr/bin/env bash
# docker-run.sh — convenience wrapper for running wifi-auditor in Docker
#
# USB Passthrough Notes:
#   1. Plug in your wireless adapter BEFORE running this script.
#   2. The container gets access to /dev/bus/usb (all USB devices).
#   3. Inside the container, run `iw dev` to verify the adapter is visible.
#   4. If the adapter doesn't appear, check `lsusb` on the host; the USB
#      device must be connected and the driver must support injection.
#
# Usage:
#   sudo ./docker-run.sh                          # interactive menu
#   sudo ./docker-run.sh --preflight              # pre-flight check
#   sudo ./docker-run.sh --headless \             # headless scan
#       --scope scope.yaml \
#       --target AA:BB:CC:DD:EE:FF \
#       --auto

set -euo pipefail

IMAGE="wifi-auditor:latest"
CONTAINER_NAME="wifi-auditor-$(date +%s)"

# Build if image doesn't exist
if ! docker image inspect "$IMAGE" &>/dev/null; then
    echo "[*] Image not found — building..."
    docker build -t "$IMAGE" .
fi

# Ensure data directories exist on host
mkdir -p captures wordlists results

docker run \
    --rm \
    --interactive \
    --tty \
    --name "$CONTAINER_NAME" \
    --privileged \
    --network host \
    --device /dev/bus/usb \
    --volume "$(pwd)/captures:/opt/wifi-auditor/captures" \
    --volume "$(pwd)/wordlists:/opt/wifi-auditor/wordlists" \
    --volume "$(pwd)/results:/opt/wifi-auditor/results" \
    --volume "$(pwd)/scope.yaml:/opt/wifi-auditor/scope.yaml:ro" \
    "$IMAGE" \
    "$@"
