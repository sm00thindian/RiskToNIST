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
pip install --upgrade pip --quiet --trusted-host pypi.org --trusted-host files.pythonhosted.org
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt --quiet --trusted-host pypi.org --trusted-host files.pythonhosted.org
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

# Generate nist_controls.json from OSCAL catalog
echo "Generating nist_controls.json from NIST SP 800-53 catalog..."
python3 utils/generate_nist_controls.py >> outputs/run.log 2>&1
if [ ! -f "data/nist_controls.json" ]; then
    echo "Error: Failed to generate nist_controls.json. Check outputs/run.log for errors."
    exit 1
fi

# Download datasets and generate outputs
echo "Running the RiskToNIST project to download datasets and generate outputs..."
python3 main.py >> outputs/run.log 2>&1

# Check if outputs were generated
if [ -f "outputs/controls.json" ] && [ -f "outputs/controls.html" ]; then
    echo "Outputs successfully generated in 'outputs/' directory:"
    echo "- JSON output: outputs/controls.json"
    echo "- HTML output: outputs/controls.html (open in a browser)"
    echo "- Log file: outputs/run.log"
else
    echo "Error: Failed to generate outputs. Check logs in outputs/run.log for errors."
    exit 1
fi

echo "Setup complete! To work in the virtual environment, run:"
echo "source venv/bin/activate"
echo "To re-run the project, use: python3 main.py >> outputs/run.log 2>&1"
echo "To regenerate nist_controls.json, use: python3 utils/generate_nist_controls.py >> outputs/run.log 2>&1"
echo "Check outputs/run.log for detailed logs."
