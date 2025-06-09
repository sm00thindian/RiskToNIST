#!/bin/bash

set -e

echo "Checking for Python3..."
if ! command -v python3 &> /dev/null; then
    echo "Python3 is not installed. Please install Python3 and try again."
    exit 1
fi

echo "Checking Python version..."
PYTHON_VERSION=$(python3 --version | awk '{print $2}')
MINIMUM_VERSION="3.7"
if [[ "$(printf '%s\n' "$PYTHON_VERSION" "$MINIMUM_VERSION" | sort -V | head -n1)" != "$MINIMUM_VERSION" ]]; then
    echo "Python version $PYTHON_VERSION is too old. Please use Python 3.7 or newer."
    exit 1
fi

echo "Checking OpenSSL version..."
PYTHON_OPENSSL_VERSION=$(python3 -c "import ssl; print(ssl.OPENSSL_VERSION)" 2>/dev/null || echo "Unknown")
echo "Python is using: $PYTHON_OPENSSL_VERSION"
if [[ "$PYTHON_OPENSSL_VERSION" =~ "OpenSSL 1.0" ]]; then
    echo "Detected OpenSSL 1.0.x, ensuring urllib3<2.0 is used."
fi

echo "Creating virtual environment..."
if [ -d "venv" ]; then
    echo "Removing existing virtual environment..."
    rm -rf venv
fi
python3 -m venv venv

echo "Activating virtual environment..."
source venv/bin/activate

echo "Upgrading pip..."
pip install --upgrade pip

echo "Installing dependencies..."
pip install -r requirements.txt

echo "Checking data files..."
DATA_FILES=("cisa_kev.json" "cisa_kev_schema.json" "attack_mapping.json" "kev_attack_mapping.json" "nist_sp800_53_catalog.json")
for FILE in "${DATA_FILES[@]}"; do
    if [ ! -f "data/$FILE" ]; then
        echo "Warning: $FILE not found in data/. Attempting to download..."
        python -c "from src.data_ingestion import download_data; import json; with open('config.json', 'r') as f: config = json.load(f); download_data([s for s in config['sources'] if s['output'] == '$FILE'])" 2>&1 | tee -a download.log
        if [ ! -f "data/$FILE" ]; then
            echo "Error: Failed to download $FILE. Check download.log for details."
            echo "For attack_mapping.json or kev_attack_mapping.json, consider using local files:"
            echo "  cp /path/to/$FILE data/$FILE"
            echo "Update config.json with: \"url\": \"file:///path/to/$FILE\""
            exit 1
        fi
    fi
done

echo "Running Risktonist..."
python run.py 2>&1 | tee run.log

echo "Execution completed. Check run.log for details."
