#!/bin/sh

# Exit immediately if a command exits with a non-zero status.
set -e

# Start the Uvicorn server
uvicorn main:app --host 0.0.0.0 --port "$PORT"
