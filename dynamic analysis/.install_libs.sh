#!/bin/bash

# =============================================================================
# Script to Install libtool-bin and python3-venv
# =============================================================================
#
# Description:
#   Installs the libtool-bin and python3-venv packages on Debian-based systems.
#
# Usage:
#   sudo ./install_libtool_python3venv.sh
#
# =============================================================================

set -euo pipefail  # Enable strict error handling
# set -x  # Uncomment for debugging

# ------------------------------
# Helper Functions
# ------------------------------

# Function to print success messages
print_success() {
  echo -e "\e[32m$1\e[0m"
}

# Function to print warning messages
print_warning() {
  echo -e "\e[33m$1\e[0m"
}

# Function to print error messages
print_error() {
  echo -e "\e[31m$1\e[0m"
}

# Function to detect the package manager
detect_package_manager() {
  if command -v apt &>/dev/null; then
    PACKAGE_MANAGER="apt"
  else
    print_error "Unsupported package manager. This script supports 'apt' only."
    exit 1
  fi
  print_success "Detected package manager: $PACKAGE_MANAGER"
}

# Function to install a package if not already installed
install_package_if_missing() {
  local pkg="$1"
  local cmd="$2"  # Command to check, if applicable

  if [ -n "$cmd" ]; then
    if ! command -v "$cmd" &>/dev/null; then
      print_warning "$pkg is not installed. Installing..."
      case "$PACKAGE_MANAGER" in
        apt)
          apt update && apt install -y "$pkg"
          ;;
      esac
      print_success "$pkg installed successfully."
    else
      print_success "$pkg is already installed. Skipping..."
    fi
  else
    # If no command is associated, check via dpkg
    if ! dpkg -l | grep -qw "$pkg"; then
      print_warning "$pkg is not installed. Installing..."
      case "$PACKAGE_MANAGER" in
        apt)
          apt update && apt install -y "$pkg"
          ;;
      esac
      print_success "$pkg installed successfully."
    else
      print_success "$pkg is already installed. Skipping..."
    fi
  fi
}

# ------------------------------
# Main Installation Function
# ------------------------------

main() {
  echo "============================================="
  echo "  Installing libtool-bin and python3-venv"
  echo "============================================="

  # Detect package manager
  detect_package_manager

  # Install libtool-bin (checks for the 'libtool' command)
  install_package_if_missing "libtool-bin" "libtool"

  # Install python3-venv (no associated command)
  install_package_if_missing "python3-venv" ""

  print_success "libtool-bin and python3-venv are installed and up-to-date."
  echo "--------------------------------------------------"
  echo "You can now proceed with your main setup script."
  echo "--------------------------------------------------"
}

# Execute the main function
main
