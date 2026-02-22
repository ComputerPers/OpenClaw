#!/bin/sh
set -e

# Python packages directory
PYTHON_PACKAGES_DIR="/home/node/.local/lib/python-packages"
REQUIREMENTS_FILE="/home/node/.openclaw/requirements.txt"
TARGET_USER="${OPENCLAW_USER:-node}"

# Function to run command as target user
run_as_user() {
    if [ "$(id -u)" -eq 0 ]; then
        su-exec "$TARGET_USER" "$@" 2>/dev/null || sudo -u "$TARGET_USER" "$@" 2>/dev/null || su "$TARGET_USER" -c "$*"
    else
        "$@"
    fi
}

# Only run package installation if we're root
if [ "$(id -u)" -eq 0 ]; then
    # Check if requirements.txt exists and install packages
    if [ -f "$REQUIREMENTS_FILE" ]; then
        echo "Found requirements.txt, installing Python packages as root..."

        # Check if pip3 is available
        if ! command -v pip3 >/dev/null 2>&1; then
            echo "ERROR: pip3 is not available in this container."
            echo "This should not happen with the custom Python image."
            echo "Please rebuild the image or check the Dockerfile."
        else
            # Ensure the packages directory exists and has correct ownership
            mkdir -p "$PYTHON_PACKAGES_DIR"

            # Get the UID/GID of the target user
            USER_ID=$(id -u "$TARGET_USER" 2>/dev/null || echo "1000")
            GROUP_ID=$(id -g "$TARGET_USER" 2>/dev/null || echo "1000")

            # Install packages to persistent directory
            echo "Installing packages from requirements.txt..."
            pip3 install --break-system-packages --target="$PYTHON_PACKAGES_DIR" -r "$REQUIREMENTS_FILE" 2>&1 | grep -v "WARNING:" | grep -E "Successfully installed|Requirement already satisfied|Collecting" || true

            # Fix ownership of installed packages
            chown -R "${USER_ID}:${GROUP_ID}" "$PYTHON_PACKAGES_DIR" 2>/dev/null || true
            chown -R "${USER_ID}:${GROUP_ID}" /home/node/.openclaw 2>/dev/null || true

            echo "Python packages installed successfully."
        fi
    else
        echo "No requirements.txt found, skipping Python package installation."
    fi
fi

# Set PYTHONPATH for the main process
export PYTHONPATH="${PYTHON_PACKAGES_DIR}:${PYTHONPATH}"

# Switch to target user and execute the main command
if [ "$(id -u)" -eq 0 ] && [ "$TARGET_USER" != "root" ]; then
    echo "Switching to user: $TARGET_USER"
    # Try different methods to switch user
    if command -v su-exec >/dev/null 2>&1; then
        exec su-exec "$TARGET_USER" "$@"
    elif command -v gosu >/dev/null 2>&1; then
        exec gosu "$TARGET_USER" "$@"
    elif command -v sudo >/dev/null 2>&1; then
        exec sudo -u "$TARGET_USER" -E "$@"
    else
        exec su "$TARGET_USER" -c "export PYTHONPATH='$PYTHONPATH'; exec $*"
    fi
else
    # Already running as correct user or no user switch needed
    exec "$@"
fi
