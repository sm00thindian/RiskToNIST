#!/bin/bash

# setup.sh: Script to set up and run the RiskToNIST project.
# Ensures Python dependencies are installed, data files are present, output directory is created,
# and executes the main script. Manages log rotation with configurable retention period using Python.

set -e  # Exit on any error

# Function to rotate run.log and enforce retention policy
rotate_log() {
    local log_file="run.log"
    local config_file="config.json"
    local retention_days=30  # Default retention period

    # Read retention_days from config.json using Python
    if [ -f "$config_file" ]; then
        cat << EOF > temp_config_parser.py
import json
import sys

try:
    with open('$config_file', 'r') as f:
        config = json.load(f)
    retention_days = config.get('logging', {}).get('retention_days', 30)
    if not isinstance(retention_days, int) or retention_days <= 0:
        print(f"Warning: Invalid retention_days ({retention_days}) in $config_file. Using default (30 days).")
        retention_days = 30
    print(retention_days)
except Exception as e:
    print(f"Warning: Failed to parse retention_days from $config_file: {e}. Using default (30 days).")
    print(30)
EOF
        retention_days=$(python3 temp_config_parser.py 2>/dev/null) || {
            echo "Warning: Failed to run config parser. Using default retention period ($retention_days days)."
        }
        rm -f temp_config_parser.py
    else
        echo "Warning: $config_file missing. Using default retention period ($retention_days days)."
    fi

    # Rotate existing run.log
    if [ -f "$log_file" ]; then
        local timestamp=$(date +%Y%m%d_%H%M)
        mv "$log_file" "${log_file%.*}_$timestamp.log" || {
            echo "Warning: Failed to rotate $log_file. Continuing..."
        }
    fi

    # Clean up old log files based on retention_days
    echo "Cleaning up log files older than $retention_days days..."
    find . -name "run_*.log" -mtime "+$retention_days" -delete 2>/dev/null || {
        echo "Warning: Failed to delete old log files. Check permissions."
    }

    # Redirect all output to new run.log
    exec > >(tee -a run.log) 2>&1
}

# Function to ensure the output directory exists
ensure_output_directory() {
    local output_dir="output"
    echo "Ensuring output directory exists..."
    mkdir -p "$output_dir" || {
        echo "Error: Failed to create output directory $output_dir"
        exit 1
    }
    echo "Output directory $output_dir ready"
}

# Function to check and install Python dependencies
check_requirements() {
    echo "Checking Python dependencies..."
    if ! command -v python3 &> /dev/null; then
        echo "Error: Python 3 is not installed. Please install Python 3."
        exit 1
    fi

    echo "Upgrading pip..."
    python3 -m pip install --quiet --upgrade pip &> /dev/null || {
        echo "Error: Failed to upgrade pip. Check network or permissions."
        exit 1
    }

    echo "Installing dependencies from requirements.txt..."
    python3 -m pip install -r requirements.txt --trusted-host pypi.org --trusted-host files.pythonhosted.org --quiet || {
        echo "Error: Failed to install dependencies. Check requirements.txt or network."
        exit 1
    }
}

# Function to check data files and attempt to download if missing
check_data_files() {
    echo "Checking data files..."
    local data_files=(
        "data/cisa_kev.json"
        "data/nist_sp800_53_catalog.json"
        "data/attack_mapping.json"
        "data/kev_attack_mapping.json"
    )

    for file in "${data_files[@]}"; do
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
    if not sources:
        print(f"Error: No source found for $(basename "$file") in config.json")
        exit(1)
    download_data(sources)
except Exception as e:
    print(f"Error: Failed to download $(basename "$file"). Check download.log for details.")
    print(f"For attack_mapping.json or kev_attack_mapping.json, consider using local files:")
    print(f"  cp /path/to/$(basename "$file") data/$(basename "$file")")
    print(f"Update config.json with: \"url\": \"file:///path/to/$(basename "$file")\"")
    exit(1)
EOF
            python3 temp_download.py || {
                rm -f temp_download.py
                exit 1
            }
            rm -f temp_download.py
        fi
    done
}

# Function to run the main script
run_main() {
    echo "Executing main script..."
    [ -f "run.py" ] || { echo "Error: run.py not found"; exit 1; }
    python3 run.py || {
        echo "Error: Failed to execute run.py"
        exit 1
    }
    [ -f "src/env/main.py" ] || { echo "Error: src/env/main.py not found"; exit 1; }
    python3 src/env/main.py || {
        echo "Error: Failed to execute src/env/main.py"
        exit 1
    }
}

# Main execution
echo "Starting RiskToNIST execution..."
rotate_log
ensure_output_directory
check_requirements
check_data_files
run_main

echo "Execution completed. Check run.log for details and output files in the 'output' directory (risk_assessment*)."
