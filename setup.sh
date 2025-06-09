#!/bin/bash

set -e

echo "Running RiskToNIST..."

# Redirect all output to run.log
exec > >(tee -a run.log) 2>&1

# Function to check and install Python dependencies
check_requirements() {
    echo "Checking Python dependencies..."
    if ! command -v python3 &> /dev/null; then
        echo "Error: Python 3 is not installed. Please install Python 3."
        exit 1
    fi

    python3 -m pip install --upgrade pip &> /dev/null
    python3 -m pip install -r requirements.txt --trusted-host pypi.org --trusted-host files.pythonhosted.org
}

# Function to check data files and attempt to download if missing
check_data_files() {
    echo "Checking data files..."
    for file in data/cisa_kev.json data/nist_sp800_53_catalog.json data/attack_mapping.json data/kev_attack_mapping.json; do
        if [ ! -f "$file" ]; then
            echo "Warning: $file not found in data/. Attempting to download..."
            # Create a temporary Python script to handle download
            cat << EOF > temp_download.py
import json
from src.data_ingestion import download_data

try:
    with open('config.json', 'r') as f:
        config = json.load(f)
    sources = [s for s in config['sources'] if s['output'] == '$(basename "$file")']
    download_data(sources)
except Exception as e:
    print(f"Error: Failed to download $(basename "$file"). Check download.log for details.")
    print(f"For attack_mapping.json or kev_attack_mapping.json, consider using local files:")
    print(f"  cp /path/to/$(basename "$file") data/$(basename "$file")")
    print(f"Update config.json with: \"url\": \"file:///path/to/$(basename "$file")\"")
    raise
EOF
            python3 temp_download.py || exit 1
            rm temp_download.py
        fi
    done
}

# Function to run the main script
run_main() {
    echo "Executing main script..."
    python3 run.py
}

# Main execution
check_requirements
check_data_files
run_main

echo "Execution completed. Check run.log for details."
