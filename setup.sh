#!/bin/bash

# setup.sh: Script to set up and run the RiskToNIST project.
# Ensures Python dependencies are installed, data files are present, output and log directories
# are created, and executes the main script. Manages log rotation with configurable retention
# period and maximum file limit.

set -e  # Exit on any error

# Function to rotate run.log and enforce retention policy
rotate_log() {
    local config_file="config.json"
    local log_dir="logs"
    local log_file="run.log"
    local retention_days=30
    local max_log_files=10

    # Read logging settings from config.json using Python
    if [ -f "$config_file" ]; then
        log_dir=$(python3 utils/parse_config.py get logging.directory logs 2>/dev/null) || {
            echo "Warning: Failed to parse logging.directory. Using default ($log_dir)."
        }
        retention_days=$(python3 utils/parse_config.py get logging.retention_days 30 2>/dev/null) || {
            echo "Warning: Failed to parse logging.retention_days. Using default ($retention_days)."
        }
        max_log_files=$(python3 utils/parse_config.py get logging.max_log_files 10 2>/dev/null) || {
            echo "Warning: Failed to parse logging.max_log_files. Using default ($max_log_files)."
        }

        # Validate retention_days and max_log_files
        if ! [[ "$retention_days" =~ ^[0-9]+$ ]] || [ "$retention_days" -le 0 ]; then
            echo "Warning: Invalid retention_days ($retention_days) in $config_file. Using default (30 days)."
            retention_days=30
        fi
        if ! [[ "$max_log_files" =~ ^[0-9]+$ ]] || [ "$max_log_files" -le 0 ]; then
            echo "Warning: Invalid max_log_files ($max_log_files) in $config_file. Using default (10)."
            max_log_files=10
        fi
    else
        echo "Warning: $config_file missing. Using default logging settings (dir=$log_dir, retention=$retention_days days, max_files=$max_log_files)."
    fi

    # Ensure log directory exists
    mkdir -p "$log_dir" || {
        echo "Error: Failed to create log directory $log_dir"
        exit 1
    }

    # Rotate existing run.log
    local full_log_file="$log_dir/$log_file"
    if [ -f "$full_log_file" ]; then
        local timestamp=$(date +%Y%m%d_%H%M)
        mv "$full_log_file" "$log_dir/${log_file%.*}_$timestamp.log" || {
            echo "Warning: Failed to rotate $full_log_file. Continuing..."
        }
    fi

    # Clean up old log files based on retention_days
    echo "Cleaning up log files older than $retention_days days..."
    find "$log_dir" -name "run_*.log" -mtime "+$retention_days" -delete 2>/dev/null || {
        echo "Warning: Failed to delete old log files. Check permissions."
    }

    # Enforce maximum log file limit
    echo "Enforcing maximum of $max_log_files log files..."
    ls -t "$log_dir/run_*.log" 2>/dev/null | tail -n +"$((max_log_files + 1))" | xargs -I {} rm "$log_dir/{}" 2>/dev/null || {
        echo "Warning: Failed to enforce max_log_files limit. Check permissions."
    }

    # Redirect all output to new run.log
    exec > >(tee -a "$full_log_file") 2>&1
}

# Function to ensure the output directory exists
ensure_output_directory() {
    local output_dir="output"
    # Read output directory from config.json
    if [ -f "config.json" ]; then
        output_dir=$(python3 utils/parse_config.py get output.directory output 2>/dev/null) || {
            echo "Warning: Failed to parse output.directory. Using default ($output_dir)."
        }
    fi
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
            python3 utils/parse_config.py download "$(basename "$file")" || {
                echo "Error: Failed to download $file"
                exit 1
            }
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

echo "Execution completed. Check logs/run.log for details and output files in the 'output' directory (risk_assessment*)."
