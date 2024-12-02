#!/bin/bash

# =============================================================================
# Malware Analysis Environment Setup Script
# =============================================================================
#
# Description:
#   Automates the setup of a malware analysis environment by installing required
#   system tools, setting up Python virtual environments, and pushing precompiled
#   binaries (strace, inotify-tools, tcpdump) to the Android emulator for dynamic analysis.
#
# Prerequisites:
#   - Linux-based system (Debian, Ubuntu)
#   - Sudo privileges
#   - Android emulator installed and running
#   - Android NDK located at /home/whiterabbit/Android/android-ndk-r27c
#   - `python3-venv` and `libtool-bin` installed manually
#   - Manually compiled `strace`, `inotify-tools`, and `tcpdump` placed in $TOOLS_DIR
#
# Usage:
#   sudo ./envi_set.sh
#
# Notes:
#   - Ensure that the Android emulator is running before executing the script.
#   - The script creates necessary directories and handles permissions.
#   - Logs are saved to setup_environment.log for troubleshooting.
#
# Troubleshooting:
#   - If adb root fails, ensure that the emulator supports root access.
#   - Verify that the NDK path is correct and contains libc++_shared.so.
#   - Check setup_environment.log for detailed logs.
#
# =============================================================================

set -euo pipefail  # Enable strict error handling
# set -x           # Enable debugging (uncomment for debugging)

# ------------------------------
# Configuration Variables
# ------------------------------

# Log file for capturing all script output
LOGFILE="setup_environment.log"

# Clean up the existing log file
rm -f "$LOGFILE"

# Redirect all output (stdout and stderr) to the log file with timestamps
exec > >(while IFS= read -r line; do echo "$(date '+%Y-%m-%d %H:%M:%S') - $line"; done | tee -a "$LOGFILE") 2>&1

# Determine the non-root user's home directory
if [ "$EUID" -eq 0 ]; then
    if [ -n "${SUDO_USER:-}" ]; then
        USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
    else
        echo -e "\e[31mCannot determine the non-root user. Please run the script using sudo with a specified user.\e[0m" >&2
        exit 1
    fi
else
    USER_HOME="$HOME"
fi

# Base directory for the project
BASE_DIR="$USER_HOME/Capstone_white-rabbit/Android"

# Paths to necessary directories and files
TOOLS_DIR="$USER_HOME/tools_dy"
NDK_DIR="/home/whiterabbit/Android/android-ndk-r27c"  # Update this path if necessary
RESULTS_DIR="$BASE_DIR/dynamic_analysis_results"
MALICIOUS_APKS_DIR="$USER_HOME/Capstone_white-rabbit/Documents/malicious_apk/apks"

# Path to libc++_shared.so (set to the specified location)
LIBC_PATH="$NDK_DIR/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/x86_64-linux-android/libc++_shared.so"

# Python virtual environment directory
VENV_DIR="$BASE_DIR/myenv"

# List of required executable commands
REQUIRED_COMMANDS=("adb" "fastboot" "make" "gcc" "g++" "git" "autoconf" "automake" "pkg-config" "flex" "bison" "unzip")

# List of required packages without direct executables
REQUIRED_PACKAGES=()

# List of required device binaries with their relative paths
declare -A binaries_paths=(
  ["strace"]="strace/strace"
  ["inotifywait"]="inotify-tools/src/inotifywait"
  ["tcpdump"]="tcpdump/tcpdump"
)

# Android API level (set to 27 as per requirement)
API_LEVEL=27

# ------------------------------
# Helper Functions
# ------------------------------

# Function to print success messages (to stderr)
print_success() {
  echo -e "\e[32m$1\e[0m" >&2
}

# Function to print warning messages (to stderr)
print_warning() {
  echo -e "\e[33m$1\e[0m" >&2
}

# Function to print error messages (to stderr)
print_error() {
  echo -e "\e[31m$1\e[0m" >&2
}

# Function to check if the script is run as root
check_root() {
  if [ "$EUID" -ne 0 ]; then
    print_error "Please run this script as root or use sudo."
    exit 1
  fi
}

# Function to detect the package manager
detect_package_manager() {
  if command -v apt &>/dev/null; then
    PACKAGE_MANAGER="apt"
  elif command -v dnf &>/dev/null; then
    PACKAGE_MANAGER="dnf"
  elif command -v pacman &>/dev/null; then
    PACKAGE_MANAGER="pacman"
  else
    print_error "Unsupported package manager. Please install dependencies manually."
    exit 1
  fi
  print_success "Detected package manager: $PACKAGE_MANAGER"
}

# Function to check if a package is installed for a specific architecture
is_package_installed() {
  local pkg="$1"
  local arch="$2"
  dpkg -l | grep -qw "${pkg}:${arch}"
}

# Function to install a package for a specific architecture
install_package() {
  local pkg="$1"
  local arch="$2"

  if ! is_package_installed "$pkg" "$arch"; then
    print_warning "$pkg for $arch architecture is not installed. Installing..."
    case "$PACKAGE_MANAGER" in
      apt)
        apt-get update
        apt-get install -y "${pkg}:${arch}"
        ;;
      dnf)
        dnf install -y "${pkg}.${arch}"
        ;;
      pacman)
        pacman -Syu --noconfirm "${pkg}"
        ;;
      *)
        print_error "Package manager $PACKAGE_MANAGER is not supported by this script."
        exit 1
        ;;
    esac
    print_success "$pkg for $arch architecture installed successfully."
  else
    print_success "$pkg for $arch architecture is already installed. Skipping..."
  fi
}

# Function to install required executable commands
install_required_commands() {
  print_success "Installing required system commands..."
  for cmd in "${REQUIRED_COMMANDS[@]}"; do
    if ! command -v "$cmd" &>/dev/null; then
      print_warning "$cmd is not installed. Installing..."
      case "$PACKAGE_MANAGER" in
        apt)
          apt-get install -y "$cmd"
          ;;
        dnf)
          dnf install -y "$cmd"
          ;;
        pacman)
          pacman -S --noconfirm "$cmd"
          ;;
      esac
      print_success "$cmd installed successfully."
    else
      print_success "$cmd is already installed. Skipping..."
    fi
  done
}

# Function to install required system packages
install_required_packages() {
  print_success "Installing required system packages..."
  for pkg in "${REQUIRED_PACKAGES[@]}"; do
    if ! dpkg -l | grep -qw "${pkg}:amd64"; then
      print_warning "$pkg for amd64 architecture is not installed. Installing..."
      case "$PACKAGE_MANAGER" in
        apt)
          apt-get update
          apt-get install -y "${pkg}:amd64"
          ;;
        dnf)
          dnf install -y "${pkg}.x86_64"
          ;;
        pacman)
          pacman -S --noconfirm "$pkg"
          ;;
      esac
      print_success "$pkg for amd64 architecture installed successfully."
    else
      print_success "$pkg for amd64 architecture is already installed. Skipping..."
    fi
  done
}

# Function to create necessary project directories
create_project_directories() {
  print_success "Setting up project directories..."
  
  # Debugging: Print the value of SUDO_USER
  echo "DEBUG: SUDO_USER is set to '$SUDO_USER'" >&2

  mkdir -p "$BASE_DIR" "$RESULTS_DIR" "$MALICIOUS_APKS_DIR" "$TOOLS_DIR" || {
    print_error "Failed to create project directories."
    exit 1
  }
  echo "DEBUG: Directories created successfully." >&2

  # Change ownership to the non-root user
  if [ -n "${SUDO_USER:-}" ]; then
    chown -R "$SUDO_USER":"$SUDO_USER" "$BASE_DIR" "$RESULTS_DIR" "$MALICIOUS_APKS_DIR" "$TOOLS_DIR" || {
      print_error "Failed to change ownership of project directories to '$SUDO_USER'."
      exit 1
    }
    print_success "Changed ownership of project directories to '$SUDO_USER'."
  else
    print_error "SUDO_USER is not set. Cannot change ownership of project directories."
    exit 1
  fi

  print_success "Project directories are set up at:"
  echo "  Project Directory: $BASE_DIR" >&2
  echo "  Results Directory: $RESULTS_DIR" >&2
  echo "  Malicious APKs Directory: $MALICIOUS_APKS_DIR" >&2
  echo "  Tools Directory: $TOOLS_DIR" >&2
}

# Function to set up Python virtual environment
setup_python_virtualenv() {
  print_success "Setting up Python virtual environment..."
  if [ ! -d "$VENV_DIR" ]; then
    print_warning "Creating a new virtual environment at $VENV_DIR..."
    python3 -m venv "$VENV_DIR" || {
      print_error "Failed to create Python virtual environment."
      exit 1
    }
    print_success "Virtual environment created."
  else
    print_success "Virtual environment already exists at $VENV_DIR. Skipping creation."
  fi

  print_success "To activate the Python virtual environment, run:"
  echo "  source \"$VENV_DIR/bin/activate\"" >&2
}

# Function to install Python dependencies as the non-root user
install_python_dependencies() {
  print_success "Installing Python dependencies..."

  # Execute pip commands as the non-root user without using heredoc
  sudo -u "$SUDO_USER" bash -c "
    source \"${VENV_DIR}/bin/activate\" && \
    pip install --upgrade pip && \
    pip install -q pyzipper androguard && \
    echo 'Python packages pyzipper and androguard installed successfully.'
  " || {
    print_error "Failed to install Python dependencies."
    exit 1
  }

  print_success "Python dependencies installed successfully."
}

# Function to validate Android NDK installation
validate_ndk() {
  print_success "Validating Android NDK installation..."
  if [ ! -d "$NDK_DIR" ]; then
    print_error "Android NDK not found at $NDK_DIR. Please ensure it is installed."
    exit 1
  fi

  # Check for libc++_shared.so at the specified path
  if [ ! -f "$LIBC_PATH" ]; then
    print_error "libc++_shared.so not found at $LIBC_PATH."
    exit 1
  fi

  print_success "Android NDK is properly installed."
}

# Function to verify ADB connection
verify_adb_connection() {
  print_success "Verifying ADB connection..."
  DEVICE_COUNT=$(adb devices | awk 'NR>1 {print $2}' | grep -c "^device$")

  if [ "$DEVICE_COUNT" -ge 1 ]; then
    print_success "ADB connection verified: $DEVICE_COUNT device(s) connected."
  else
    print_error "No emulator or device detected. Please start an emulator or connect a device."
    exit 1
  fi
}

# Function to get device architecture
get_device_architecture() {
  print_success "Determining device architecture..."
  DEVICE_ARCH=$(adb shell getprop ro.product.cpu.abi | tr -d '\r')

  if [ -z "$DEVICE_ARCH" ]; then
    print_error "Unable to determine device architecture."
    exit 1
  fi

  print_success "Detected device architecture: $DEVICE_ARCH"
  echo "$DEVICE_ARCH"
}

# Function to map device architecture to binary architecture
map_architecture() {
  local arch="$1"
  case "$arch" in
    arm64-v8a)
      echo "aarch64-linux-android"
      ;;
    armeabi-v7a)
      echo "arm-linux-androideabi"
      ;;
    x86_64)
      echo "x86_64-linux-android"
      ;;
    x86)
      echo "i686-linux-android"
      ;;
    *)
      print_error "Unsupported device architecture: $arch"
      exit 1
      ;;
  esac
}

# Function to set cross-compilation variables
set_cross_compile_vars() {
  local target_host="$1"
  
  # Define the API level and set up cross-compilation tools
  export TARGET_HOST="$target_host"
  export API="$API_LEVEL"
  
  # Define the cross-compiler based on target host
  case "$TARGET_HOST" in
    aarch64-linux-android)
      export CC="$NDK_DIR/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android${API}-clang"
      ;;
    arm-linux-androideabi)
      export CC="$NDK_DIR/toolchains/llvm/prebuilt/linux-x86_64/bin/armv7a-linux-androideabi${API}-clang"
      ;;
    x86_64-linux-android)
      export CC="$NDK_DIR/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android${API}-clang"
      ;;
    i686-linux-android)
      export CC="$NDK_DIR/toolchains/llvm/prebuilt/linux-x86_64/bin/i686-linux-android${API}-clang"
      ;;
    *)
      print_error "Unsupported target host: $TARGET_HOST"
      exit 1
      ;;
  esac

  print_success "Cross-compiler set to $CC"
}

# ------------------------------
# Function to Push Compiled Binaries to Emulator
# ------------------------------

push_compiled_binaries() {
  print_success "Pushing compiled binaries to the emulator..."

  # Define the list of binaries and their relative paths within TOOLS_DIR
  declare -A binaries_paths=(
    ["strace"]="strace/strace"
    ["inotifywait"]="inotify-tools/src/inotifywait"
    ["tcpdump"]="tcpdump/tcpdump"
  )

  # Iterate over each binary and push to emulator
  for binary in "${!binaries_paths[@]}"; do
      local relative_path="${binaries_paths[$binary]}"
      local source_path="${TOOLS_DIR}/${relative_path}"
      local target_path="/data/local/tmp/$binary"

      if [ -f "$source_path" ]; then
          print_success "Pushing $binary to emulator..."
          adb push "$source_path" "$target_path" || {
              print_error "Failed to push $binary to $target_path."
              exit 1
          }
          adb shell chmod 755 "$target_path" || {
              print_error "Failed to set executable permissions for $binary on the emulator."
              exit 1
          }
          print_success "$binary pushed successfully to $target_path."
      else
          print_error "Binary $binary not found at ${source_path}. Please ensure it is compiled correctly."
          exit 1
      fi
  done

  # Echo confirmation after all binaries have been pushed
  print_success "All tools (strace, tcpdump, inotifywait) have been successfully pushed to the emulator."
}

# ------------------------------
# Function to Push libc++_shared.so to Emulator
# ------------------------------

push_libc() {
  print_success "Pushing libc++_shared.so to the emulator..."
  if [ -f "$LIBC_PATH" ]; then
      adb push "$LIBC_PATH" "/data/local/tmp/libc++_shared.so" || {
          print_error "Failed to push libc++_shared.so to the emulator."
          exit 1
      }
      adb shell chmod 755 "/data/local/tmp/libc++_shared.so" || {
          print_error "Failed to set executable permissions for libc++_shared.so on the emulator."
          exit 1
      }
      print_success "libc++_shared.so pushed successfully."
  else
      print_error "libc++_shared.so not found at $LIBC_PATH. Please check the NDK installation."
      exit 1
  fi
}

# ------------------------------
# Function to Configure and Start tcpdump on Emulator with Streaming
# ------------------------------

start_tcpdump_stream() {
  print_success "Starting tcpdump on the emulator and streaming captures to the host machine..."

  # Define the tcpdump directory on the host machine
  local TCPDUMP_DIR="$TOOLS_DIR/tcpdump"

  # Ensure the tcpdump directory exists
  if [ ! -d "$TCPDUMP_DIR" ]; then
    print_warning "tcpdump directory $TCPDUMP_DIR does not exist. Creating..."
    mkdir -p "$TCPDUMP_DIR" || {
      print_error "Failed to create tcpdump directory at $TCPDUMP_DIR."
      exit 1
    }
    print_success "tcpdump directory created at $TCPDUMP_DIR."
  fi

  # Define the local path to save the capture file with timestamp inside tcpdump directory
  local timestamp=$(date '+%Y%m%d_%H%M%S')
  local local_capture_path="$TCPDUMP_DIR/capture_${timestamp}.pcap"

  # Start streaming tcpdump output from the emulator to the local machine
  adb exec-out "/data/local/tmp/tcpdump -i any -s 0 -w - 'not port 5555'" > "$local_capture_path" &

  # Capture the PID of the background process
  TCPDUMP_STREAM_PID=$!

  # Store the PID in a file for potential future management
  echo "$TCPDUMP_STREAM_PID" > "$TCPDUMP_DIR/tcpdump_stream.pid"

  print_success "tcpdump is streaming and saving captures to $local_capture_path"
  print_success "tcpdump streaming process PID: $TCPDUMP_STREAM_PID"
}

# ------------------------------
# Function to Stop tcpdump Streaming (Optional)
# ------------------------------

stop_tcpdump_stream() {
  print_success "Stopping tcpdump streaming..."

  # Define the tcpdump directory on the host machine
  local TCPDUMP_DIR="$TOOLS_DIR/tcpdump"

  if [ -f "$TCPDUMP_DIR/tcpdump_stream.pid" ]; then
    local pid=$(cat "$TCPDUMP_DIR/tcpdump_stream.pid")
    kill "$pid" && rm "$TCPDUMP_DIR/tcpdump_stream.pid" && print_success "tcpdump streaming stopped."
  else
    print_warning "No tcpdump streaming process found."
  fi
}

# ------------------------------
# Function to Clean Up Temporary Files and Processes
# ------------------------------

cleanup() {
  print_success "Cleaning up temporary files and stopping tcpdump streaming if running..."
  
  # Stop tcpdump streaming if running
  stop_tcpdump_stream
  
  # Add any additional cleanup commands here
}

# Trap EXIT to perform cleanup
trap cleanup EXIT

# ------------------------------
# Main Setup Function
# ------------------------------

main() {
  echo "=============================================="
  echo "  Malware Analysis Environment Setup Script"
  echo "=============================================="

  # Check for root privileges
  check_root

  # Detect package manager
  detect_package_manager

  # Install required system commands
  install_required_commands

  # Install required system packages
  install_required_packages

  # Create project directories
  create_project_directories

  # Set up Python virtual environment
  setup_python_virtualenv

  # Install Python dependencies
  install_python_dependencies

  # Validate Android NDK installation
  validate_ndk

  # Verify ADB connection
  verify_adb_connection

  # Determine device architecture
  DEVICE_ARCH=$(get_device_architecture 2>/dev/null | tail -n1)
  TARGET_HOST=$(map_architecture "$DEVICE_ARCH")

  # Set cross-compilation variables
  set_cross_compile_vars "$TARGET_HOST"

  # Push compiled binaries to the emulator
  push_compiled_binaries

  # Push libc++_shared.so to the emulator
  push_libc

  # Configure and start tcpdump on the emulator with streaming
  start_tcpdump_stream

  # Final Setup Instructions
  print_success "Setup complete!"
  echo "--------------------------------------------------"
  echo "To activate the Python virtual environment, run:"
  echo "  source \"$VENV_DIR/bin/activate\""
  echo ""
  echo "To place malicious APKs, use the directory:"
  echo "  $MALICIOUS_APKS_DIR"
  echo ""
  echo "To run the malware analysis tool, execute:"
  echo "  source \"$VENV_DIR/bin/activate\""
  echo "  python \"$BASE_DIR/dev_dynamic_analysis_v2.py\""
  echo ""
  echo "tcpdump is actively capturing and saving to:"
  echo "  $TOOLS_DIR/tcpdump/capture_${timestamp}.pcap"
  echo "--------------------------------------------------"
}

# Execute the main function
main
