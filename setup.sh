#!/bin/bash

# setup.sh: Script to set up the RiskToNIST project, download datasets, and generate outputs
# Supports macOS, Ubuntu Linux, and Amazon Linux 2

set -e  # Exit on any error

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

echo "Checking system dependencies..."

# Detect operating system
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_NAME="${ID}"
    OS_VERSION="${VERSION_ID}"
elif [ "$(uname -s)" = "Darwin" ]; then
    OS_NAME="darwin"
else
    echo "Unable to detect operating system."
    exit 1
fi

# Set package manager and Python command based on OS
case "$OS_NAME" in
    darwin)  # macOS
        PKG_MANAGER="brew"
        PYTHON3="python3"
        ;;
    ubuntu)  # Ubuntu Linux
        PKG_MANAGER="apt"
        PYTHON3="python3"
        ;;
    amzn)  # Amazon Linux 2
        PKG_MANAGER="yum"
        PYTHON3="python3.8"
        ;;
    *)
        echo "Unsupported OS: $OS_NAME. This script supports macOS, Ubuntu Linux, and Amazon Linux 2."
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
    elif [ "$PKG_MANAGER" = "yum" ]; then
        echo "Ensure yum is available (should be pre-installed on Amazon Linux 2)."
    fi
    exit 1
fi

# Install system dependencies
if [ "$PKG_MANAGER" = "brew" ]; then
    echo "Installing macOS dependencies..."
    brew install python3 unzip || true  # Ignore if already installed
elif [ "$PKG_MANAGER" = "apt" ]; then
    echo "Installing Ubuntu dependencies..."
    sudo apt update -yq
    sudo apt install -yq python3 python3-venv python3-dev unzip
elif [ "$PKG_MANAGER" = "yum" ]; then
    echo "Installing Amazon Linux 2 dependencies..."
    sudo yum update -yq
    sudo amazon-linux-extras enable python3.8 >/dev/null 2>&1
    sudo yum install -yq python3.8 python3-devel gcc libffi-devel python3-pip unzip
fi

# Check for Python3
if ! command_exists "$PYTHON3"; then
    echo "Python3 is not installed. Please install Python3 (version 3.8 or higher) and try again."
    exit 1
fi

# Check Python version
PYTHON_VERSION=$("$PYTHON3" --version | awk '{print $2}')
PYTHON_MAJOR=$(echo "$PYTHON_VERSION" | cut -d. -f1)
PYTHON_MINOR=$(echo "$PYTHON_VERSION" | cut -d. -f2)
if [ "$PYTHON_MAJOR" -lt 3 ] || { [ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 8 ]; }; then
    echo "Python version $PYTHON_VERSION is too old. Requires Python 3.8 or higher."
    exit 1
fi
echo "Python $PYTHON_VERSION detected."

# Check for unzip
if ! command_exists unzip; then
    echo "unzip is not installed. Please install it (e.g., via $PKG_MANAGER)."
    exit 1
fi

echo "Setting up virtual environment..."

if [ ! -d "venv" ]; then
    "$PYTHON3" -m venv venv
else
    echo "Virtual environment already exists."
fi

# Activate virtual environment
source venv/bin/activate

echo "Installing Python dependencies..."

pip install -q --upgrade pip
if [ -f "requirements.txt" ]; then
    pip install -q -r requirements.txt || {
        echo "Error: Failed to install dependencies from requirements.txt."
        echo "Try running: pip install -r requirements.txt --verbose for details."
        exit 1
    }
else
    echo "Error: requirements.txt not found."
    exit 1
fi

echo "Creating directory structure..."

mkdir -p data mappings outputs templates

echo "Verifying main.py..."

if [ ! -f "main.py" ]; then
    echo "Error: main.py not found in the project root."
    exit 1
fi

echo "Generating nist_controls.json..."

python3 utils/generate_nist_controls.py >> outputs/run.log 2>&1
if [ ! -f "data/nist_controls.json" ]; then
    echo "Error: Failed to generate nist_controls.json. Check outputs/run.log for errors."
    exit 1
fi

echo "Running RiskToNIST project..."

{
    python3 main.py 2>&1 | tee -a outputs/run.log &
    pid=$!
    sleep 3600  # 60-minute timeout
    if kill -0 $pid 2>/dev/null; then
        echo "Error: main.py timed out after 60 minutes." | tee -a outputs/run.log
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
    echo "Setup complete. Outputs generated in 'outputs/':"
    echo "- JSON: outputs/controls.json"
    echo "- HTML: outputs/controls.html (open in a browser)"
    echo "- Log: outputs/run.log"
    echo "To work in the virtual environment, run: source venv/bin/activate"
    echo "To re-run the project, use: python3 main.py | tee -a outputs/run.log"
    echo "To regenerate nist_controls.json, use: python3 utils/generate_nist_controls.py >> outputs/run.log 2>&1"
else
    echo "Error: Failed to generate outputs. Check outputs/run.log for errors."
    exit 1
fi
