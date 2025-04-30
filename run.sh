#!/bin/bash

# Set the data directory for persistent storage
# You can customize this path as needed
export CERT_MONITOR_DATA_DIR="$HOME/.cert-monitor"

# Create the data directory if it doesn't exist
mkdir -p "$CERT_MONITOR_DATA_DIR"
echo "Using persistent storage at: $CERT_MONITOR_DATA_DIR"

# Run the Flask application
python3 app.py
