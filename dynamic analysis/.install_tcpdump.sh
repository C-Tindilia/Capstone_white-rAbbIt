#!/bin/bash

# Define target directory
TARGET_DIR="/usr/local/Capstone_white-rAbbIt/Android/Sdk/tools_dy/tcpdump"

# Install dependencies
echo "Installing dependencies for tcpdump..."
sudo apt-get update
sudo apt-get install -y libpcap-dev build-essential

# Clone the tcpdump repository
echo "Cloning the tcpdump repository..."
git clone https://github.com/the-tcpdump-group/tcpdump.git || { echo "Failed to clone tcpdump repository"; exit 1; }

# Navigate to the source directory
cd tcpdump || { echo "tcpdump directory not found"; exit 1; }

# Configure, build, and install tcpdump
echo "Building tcpdump..."
./configure || { echo "Configuration failed"; exit 1; }
make || { echo "Build failed"; exit 1; }
sudo make install || { echo "Installation failed"; exit 1; }

# Create target directory and move binary
echo "Setting up tcpdump in the target directory: $TARGET_DIR"
sudo mkdir -p "$TARGET_DIR"
sudo cp $(which tcpdump) "$TARGET_DIR/" || { echo "Failed to copy tcpdump binary"; exit 1; }

# Verify installation
echo "Verifying tcpdump installation..."
"$TARGET_DIR/tcpdump" --version || { echo "tcpdump verification failed"; exit 1; }

echo "tcpdump installation completed successfully!"
