#!/bin/bash

# setup.sh: Script to set up the RiskToNIST project, download datasets, and generate outputs
# Supports macOS and Ubuntu Linux

set -e  # Exit on any error

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

echo "Checking system dependencies..."

# Detect operating system
OS=$(uname -s)
case "$OS" in
    Darwin)  # macOS
        PKG_MANAGER="brew"
        PYTHON3="python3"
        ;;
    Linux)  # Ubuntu Linux
        PKG_MANAGER="apt"
        PYTHON3="python3"
        ;;
    *)
        echo "Unsupported OS: $OS. This script supports macOS and Ubuntu Linux."
        exit 1
        ;;
esac

# Check for package manager
if ! command_exists "$PKG_MANAGER"; then
    echo "$PKG_MANAGER is not installed."
    if [ "$PKG_MANAGER" = "brew" ]; then
        echo "Install Homebrew from https://brew.sh and try again."
    elif [ "$PKG_MANAGER" = "apt" ]; then
        echo "Ensure apt is available (should be pre-installed on Ubuntu)."
    fi
    exit 1
fi

# Install system dependencies
if [ "$PKG_MANAGER" = "brew" ]; then
    echo "Installing macOS dependencies..."
    brew install python3 unzip || true  # Ignore if already installed
elif [ "$PKG_MANAGER" = "apt" ]; then
    echo "Installing Ubuntu dependencies..."
    sudo apt update
    sudo apt install -y python3 python3-venv python3-dev unzip
fi

# Check for Python3
if ! command_exists "$PYTHON3"; then
    echo "Python3 is not installed. Please install Python3 and try again."
    exit 1
fi

# Check for unzip
if ! command_exists unzip; then
    echo "unzip is not installed. Please install it (e.g., via $PKG_MANAGER)."
    exit 1
fi

echo "Setting up virtual environment..."

if [ ! -d "venv" ]; then
    "$PYTHON3" -m venv venv
else
    echo "Virtual environment already exists, skipping creation."
fi

# Activate virtual environment
source venv/bin/activate

echo "Installing Python dependencies..."

pip install --upgrade pip --quiet --trusted-host pypi.org --trusted-host files.pythonhosted.org
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt --quiet --trusted-host pypi.org --trusted-host files.pythonhosted.org
else
    echo "Error: requirements.txt not found."
    exit 1
fi

echo "Creating directory structure..."

mkdir -p data mappings outputs templates

echo "Verifying main.py exists..."

if [ ! -f "main.py" ]; then
    echo "Error: main.py not found in the project root."
    exit 1
fi

echo "Generating nist_controls.json from NIST SP 800-53 catalog..."

python3 utils/generate_nist_controls.py >> outputs/run.log 2>&1
if [ ! -f "data/nist_controls.json" ]; then
    echo "Error: Failed to generate nist_controls.json. Check outputs/run.log for errors."
    exit 1
fi

echo "Running the RiskToNIST project to download datasets and generate outputs..."

{
    python3 main.py 2>&1 | tee -a outputs/run.log &
    pid=$!
    sleep 3600  # 60-minute timeout
    if kill -0 $pid 2>/dev/null; then
        echo "Error: main.py timed out after 60 minutes. Killing process." | tee -a outputs/run.log
        kill $pid
        exit 1
    fi
    wait $pid
} || {
    echo "Error: main.py failed. Check outputs/run.log for details." | tee -a outputs/run.log
    exit 1
}

# Check if outputs were generated
if [ -f "outputs/controls.json" ] && [ -f "outputs/controls.html" ]; then
    echo "Outputs successfully generated in 'outputs/' directory:"
    echo "- JSON output: outputs/controls.json"
    echo "- HTML output: outputs/controls.html (open in a browser)"
    echo "- Log file: outputs/run.log"
else
    echo "Error: Failed to generate outputs. Check outputs/run.log for errors."
    exit 1
fi

echo "Setup complete! To work in the virtual environment, run:"
echo "source venv/bin/activate"
echo "To re-run the project, use: python3 main.py | tee -a outputs/run.log"
echo "To regenerate nist_controls.json, use: python3 utils/generate_nist_controls.py >> outputs/run.log 2>&1"
echo "Check outputs/run.log for detailed logs."
