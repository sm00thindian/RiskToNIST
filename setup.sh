#!/bin/bash
# setup.sh: Script to fully set up the RiskToNIST project, download datasets, and generate outputs

set -e  # Exit on any error

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check system dependencies
echo "Checking system dependencies..."
if ! command_exists python3; then
    echo "Error: Python 3 is not installed. Please install it (e.g., via Homebrew: 'brew install python3')."
    exit 1
fi
if ! command_exists unzip; then
    echo "Error: unzip is not installed. Please install it (e.g., via Homebrew: 'brew install unzip')."
    exit 1
fi

# Create virtual environment if it doesn't exist
echo "Setting up virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
else
    echo "Virtual environment already exists, skipping creation."
fi

# Activate virtual environment
source venv/bin/activate

# Upgrade pip and install dependencies
echo "Installing Python dependencies..."
pip install --upgrade pip
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
else
    echo "Error: requirements.txt not found."
    exit 1
fi

# Create required directories
echo "Creating directory structure..."
mkdir -p data mappings outputs templates

# Verify main.py exists
if [ ! -f "main.py" ]; then
    echo "Error: main.py not found in the project root."
    exit 1
fi

# Download datasets and generate outputs
echo "Running the RiskToNIST project to download datasets and generate outputs..."
python3 main.py

# Check if outputs were generated
if [ -f "outputs/controls.json" ] && [ -f "outputs/controls.html" ]; then
    echo "Outputs successfully generated in 'outputs/' directory:"
    echo "- JSON output: outputs/controls.json"
    echo "- HTML output: outputs/controls.html (open in a browser)"
else
    echo "Error: Failed to generate outputs. Check logs above for errors."
    exit 1
fi

echo "Setup complete! To work in the virtual environment, run:"
echo "source venv/bin/activate"
echo "To re-run the project, use: python3 main.py"
