#!/bin/bash

# Define target directory
TARGET_DIR="/usr/local/Capstone_white-rAbbIt/Android/Sdk/tools_dy/strace"

# Install dependencies
echo "Installing dependencies for strace..."
sudo apt-get update
sudo apt-get install -y build-essential autoconf

# Clone the strace repository
echo "Cloning the strace repository..."
git clone https://github.com/strace/strace.git || { echo "Failed to clone strace repository"; exit 1; }

# Navigate to the source directory
cd strace || { echo "strace directory not found"; exit 1; }

# Configure, build, and install strace
echo "Building strace..."
./bootstrap || { echo "Bootstrap failed"; exit 1; }
./configure || { echo "Configuration failed"; exit 1; }
make || { echo "Build failed"; exit 1; }
sudo make install || { echo "Installation failed"; exit 1; }

# Create target directory and move binary
echo "Setting up strace in the target directory: $TARGET_DIR"
sudo mkdir -p "$TARGET_DIR"
sudo cp $(which strace) "$TARGET_DIR/" || { echo "Failed to copy strace binary"; exit 1; }

# Verify installation
echo "Verifying strace installation..."
"$TARGET_DIR/strace" --version || { echo "strace verification failed"; exit 1; }

echo "strace installation completed successfully!"
