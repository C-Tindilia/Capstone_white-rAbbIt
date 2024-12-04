#!/bin/bash

# Define target directory
TARGET_DIR="/usr/local/Capstone_white-rAbbIt/Android/Sdk/tools_dy/inotify-tools"

# Install dependencies
echo "Installing dependencies for inotifywait..."
sudo apt-get update
sudo apt-get install -y build-essential autotools-dev autoconf libtool

# Clone the inotify-tools repository
echo "Cloning the inotify-tools repository..."
git clone https://github.com/inotify-tools/inotify-tools.git || { echo "Failed to clone inotify-tools repository"; exit 1; }

# Navigate to the source directory
cd inotify-tools || { echo "inotify-tools directory not found"; exit 1; }

# Configure, build, and install inotify-tools
echo "Building inotify-tools..."
autoreconf -i || { echo "autoreconf failed"; exit 1; }
./configure || { echo "Configuration failed"; exit 1; }
make || { echo "Build failed"; exit 1; }
sudo make install || { echo "Installation failed"; exit 1; }

# Create target directory and move binary
echo "Setting up inotifywait in the target directory: $TARGET_DIR"
sudo mkdir -p "$TARGET_DIR"
sudo cp src/inotifywait "$TARGET_DIR/" || { echo "Failed to copy inotifywait binary"; exit 1; }

# Verify installation
echo "Verifying inotifywait installation..."
"$TARGET_DIR/inotifywait" --help || { echo "inotifywait verification failed"; exit 1; }

echo "inotifywait installation completed successfully!"
