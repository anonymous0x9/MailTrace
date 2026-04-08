#!/bin/bash

# MailTrace Setup Script
# This script installs the required dependencies for MailTrace.

echo "Setting up MailTrace..."

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "Python 3 is not installed. Please install Python 3.6 or higher."
    exit 1
fi

# Check Python version
PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
REQUIRED_VERSION="3.6"

if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
    echo "Python $PYTHON_VERSION is installed, but Python $REQUIRED_VERSION or higher is required."
    exit 1
fi

echo "Python $PYTHON_VERSION detected."

# Check if pip is installed
if ! command -v pip3 &> /dev/null; then
    echo "pip3 is not installed. Installing pip..."
    python3 -m ensurepip --upgrade
fi

# Install Rich library
echo "Installing Rich library..."
pip3 install rich

if [ $? -eq 0 ]; then
    echo "Setup complete! You can now run MailTrace with: python3 MailTrace.py"
else
    echo "Failed to install Rich. Please check your internet connection and try again."
    exit 1
fi