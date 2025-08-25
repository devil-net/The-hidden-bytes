#!/bin/sh

# Exit immediately if a command exits with a non-zero status.
set -e

# Debug: Print the PORT environment variable
echo "PORT environment variable: $PORT"

# Use PORT from environment, fallback to 3000 (Railway default)
PORT=${PORT:-3000}

# Start the Uvicorn server
uvicorn main:app --host 0.0.0.0 --port $PORT
