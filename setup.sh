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

    # Check if utils/parse_config.py exists
    [ -f "utils/parse_config.py" ] || {
        echo "Error: utils/parse_config.py not found" >&2
        exit 1
    }

    # Read logging settings from config.json using Python
    if [ -f "$config_file" ] && [ -r "$config_file" ]; then
        log_dir=$(python3 utils/parse_config.py get logging.directory logs 2>>temp_setup_errors.log) || {
            echo "Warning: Failed to parse logging.directory. Using default ($log_dir). See temp_setup_errors.log." >&2
            log_dir="logs"
        }
        retention_days=$(python3 utils/parse_config.py get logging.retention_days 30 2>>temp_setup_errors.log) || {
            echo "Warning: Failed to parse logging.retention_days. Using default ($retention_days). See temp_setup_errors.log." >&2
            retention_days=30
        }
        max_log_files=$(python3 utils/parse_config.py get logging.max_log_files 10 2>>temp_setup_errors.log) || {
            echo "Warning: Failed to parse logging.max_log_files. Using default ($max_log_files). See temp_setup_errors.log." >&2
            max_log_files=10
        }

        # Validate retention_days and max_log_files
        if ! [[ "$retention_days" =~ ^[0-9]+$ ]] || [ "$retention_days" -le 0 ]; then
            echo "Warning: Invalid retention_days ($retention_days) from config. Using default (30 days)." >&2
            retention_days=30
        fi
        if ! [[ "$max_log_files" =~ ^[0-9]+$ ]] || [ "$max_log_files" -le 0 ]; then
            echo "Warning: Invalid max_log_files ($max_log_files) from config. Using default (10)." >&2
            max_log_files=10
        fi
    else
        echo "Warning: $config_file missing or not readable. Using default logging settings (dir=$log_dir, retention=$retention_days days, max_files=$max_log_files)." >&2
    fi

    # Ensure log_dir is not empty
    [ -z "$log_dir" ] && {
        echo "Error: Log directory cannot be empty. Using default (logs)." >&2
        log_dir="logs"
    }

    # Ensure log directory exists
    mkdir -p "$log_dir" || {
        echo "Error: Failed to create log directory $log_dir" >&2
        exit 1
    }

    # Rotate existing run.log
    local full_log_file="$log_dir/$log_file"
    if [ -f "$full_log_file" ]; then
        local timestamp=$(date +%Y%m%d_%H%M)
        mv "$full_log_file" "$log_dir/${log_file%.*}_$timestamp.log" || {
            echo "Warning: Failed to rotate $full_log_file. Continuing..." >&2
        }
    fi

    # Clean up old log files based on retention_days
    echo "Cleaning up log files older than $retention_days days..."
    find "$log_dir" -name "run_*.log" -mtime "+$retention_days" -delete 2>/dev/null || {
        echo "Warning: Failed to delete old log files. Check permissions." >&2
    }

    # Enforce maximum log file limit
    echo "Enforcing maximum of $max_log_files log files..."
    ls -t "$log_dir/run_*.log" 2>/dev/null | tail -n +"$((max_log_files + 1))" | xargs -I {} rm "$log_dir/{}" 2>/dev/null || {
        echo "Warning: Failed to enforce max_log_files limit. Check permissions." >&2
    }

    # Redirect all output to new run.log
    exec > >(tee -a "$full_log_file") 2>&1
}

# Function to ensure the output directory exists
ensure_output_directory() {
    local output_dir="output"
    # Check if utils/parse_config.py exists
    [ -f "utils/parse_config.py" ] || {
        echo "Error: utils/parse_config.py not found" >&2
        exit 1
    }
    # Read output directory from config.json
    if [ -f "config.json" ] && [ -r "config.json" ]; then
        output_dir=$(python3 utils/parse_config.py get output.directory output 2>>temp_setup_errors.log) || {
            echo "Warning: Failed to parse output.directory. Using default ($output_dir). See temp_setup_errors.log." >&2
            output_dir="output"
        }
    fi
    # Ensure output_dir is not empty
    [ -z "$output_dir" ] && {
        echo "Error: Output directory cannot be empty. Using default (output)." >&2
        output_dir="output"
    }
    echo "Ensuring output directory exists..."
    mkdir -p "$output_dir" || {
        echo "Error: Failed to create output directory $output_dir" >&2
        exit 1
    }
    echo "Output directory $output_dir ready"
}

# Function to check and install Python dependencies
check_requirements() {
    echo "Checking Python dependencies..."
    if ! command -v python3 &> /dev/null; then
        echo "Error: Python 3 is not installed. Please install Python 3." >&2
        exit 1
    fi

    echo "Upgrading pip..."
    python3 -m pip install --quiet --upgrade pip &> /dev/null || {
        echo "Error: Failed to upgrade pip. Check network or permissions." >&2
        exit 1
    }

    echo "Installing dependencies from requirements.txt..."
    python3 -m pip install -r requirements.txt --trusted-host pypi.org --trusted-host files.pythonhosted.org --quiet || {
        echo "Error: Failed to install dependencies. Check requirements.txt or network." >&2
        exit 1
    }
}

# Function to check data files and attempt to download if missing
check_data_files() {
    echo "Checking data files..."
    [ -f "utils/parse_config.py" ] || {
        echo "Error: utils/parse_config.py not found" >&2
        exit 1
    }

    # Read sources from config.json
    local sources
    local failed_downloads=""
    local success_count=0
    local total_count=0
    if [ -f "config.json" ] && [ -r "config.json" ]; then
        sources=$(python3 -c "import json; print('\n'.join(s['output'] for s in json.load(open('config.json')).get('sources', []) if s.get('enabled', True)))" 2>>temp_setup_errors.log) || {
            echo "Warning: Failed to parse sources from config.json. Using default file list. See temp_setup_errors.log." >&2
            sources="
                cisa_kev.json
                cisa_kev_schema.json
                attack_mapping.json
                kev_attack_mapping.json
                nist_sp800_53_catalog.json
            "
        }
    else
        echo "Warning: config.json missing or not readable. Using default file list." >&2
        sources="
            cisa_kev.json
            cisa_kev_schema.json
            attack_mapping.json
            kev_attack_mapping.json
            nist_sp800_53_catalog.json
        "
    }

    # Ensure data directory exists and is writable
    local data_dir="data"
    mkdir -p "$data_dir" || {
        echo "Error: Failed to create data directory $data_dir" >&2
        exit 1
    }
    [ -w "$data_dir" ] || {
        echo "Error: Data directory $data_dir is not writable" >&2
        exit 1
    }

    # Check and download each file
    local max_retries=3
    local retry_delay=5
    while IFS= read -r output_filename; do
        [ -z "$output_filename" ] && continue
        local file="data/$output_filename"
        ((total_count++))
        if [ ! -f "$file" ] || [ ! -s "$file" ]; then
            echo "Warning: $file not found or empty. Attempting to download..."
            local attempt=1
            while [ $attempt -le $max_retries ]; do
                echo "Download attempt $attempt of $max_retries for $output_filename..."
                if python3 utils/parse_config.py download "$output_filename" 2>>temp_setup_errors.log; then
                    ((success_count++))
                    break
                else
                    echo "Warning: Download attempt $attempt failed for $output_filename. See temp_setup_errors.log." >&2
                    if [ $attempt -eq $max_retries ]; then
                        echo "Error: Failed to download $output_filename after $max_retries attempts." >&2
                        failed_downloads="$failed_downloads $output_filename"
                    fi
                    sleep $retry_delay
                    ((attempt++))
                fi
            done
        else
            # Validate existing JSON file
            if [[ "$output_filename" == *.json ]]; then
                python3 -c "import json; json.load(open('$file'))" 2>/dev/null || {
                    echo "Warning: Invalid JSON in $file. Attempting to redownload..."
                    local attempt=1
                    while [ $attempt -le $max_retries ]; do
                        echo "Download attempt $attempt of $max_retries for $output_filename..."
                        if python3 utils/parse_config.py download "$output_filename" 2>>temp_setup_errors.log; then
                            ((success_count++))
                            break
                        else
                            echo "Warning: Download attempt $attempt failed for $output_filename. See temp_setup_errors.log." >&2
                            if [ $attempt -eq $max_retries ]; then
                                echo "Error: Failed to download $output_filename after $max_retries attempts." >&2
                                failed_downloads="$failed_downloads $output_filename"
                            fi
                            sleep $retry_delay
                            ((attempt++))
                        fi
                    done
                }
            else
                ((success_count++))
            fi
        fi
    done <<< "$sources"

    # Print download summary
    echo "Download summary: $success_count/$total_count files successfully downloaded."
    if [ -n "$failed_downloads" ]; then
        echo "Failed downloads:$failed_downloads"
        echo "Continuing execution despite download failures. Check logs/download.log and temp_setup_errors.log for details."
    fi
}

# Function to run the main script
run_main() {
    echo "Executing main script..."
    [ -f "run.py" ] || { echo "Error: run.py not found" >&2; exit 1; }
    python3 run.py || {
        echo "Error: Failed to execute run.py" >&2
        exit 1
    }
    [ -f "src/env/main.py" ] || { echo "Error: src/env/main.py not found" >&2; exit 1; }
    python3 src/env/main.py || {
        echo "Error: Failed to execute src/env/main.py" >&2
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
rm -f temp_setup_errors.log 2>/dev/null
echo "Execution completed. Check logs/run.log for details and output files in the 'output' directory (risk_assessment*)."
