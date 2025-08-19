# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /app

# Install system dependencies for the steganography tools
# - binutils provides the 'strings' command
# - steghide is for steghide
# - binwalk is for binwalk
RUN apt-get update && apt-get install -y --no-install-recommends \
    binutils \
    steghide \
    binwalk \
    && rm -rf /var/lib/apt/lists/*

# Copy the dependencies file to the working directory
COPY requirements.txt .

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application's code to the working directory
COPY . .

# The command to run the application will be taken from railway.toml
