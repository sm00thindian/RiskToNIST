"""
utils/parse_config.py: Utility script to parse config.json for RiskToNist project.
Provides functions to read configuration values and download data files.
"""

import json
import sys
import os
import time
import requests
from src.data_ingestion import download_data

def get_config_value(key, default):
    """
    Retrieve a value from config.json using a dot-separated key path.

    Args:
        key (str): Dot-separated key path (e.g., 'logging.retention_days').
        default: Default value if the key is not found or an error occurs.

    Returns:
        The value at the specified key path or the default value.
    """
    config_file = 'config.json'
    try:
        if not os.path.isfile(config_file):
            print(f"Warning: {config_file} not found. Using default for {key} ({default}).", file=sys.stderr)
            return default
        if not os.access(config_file, os.R_OK):
            print(f"Warning: Permission denied reading {config_file}. Using default for {key} ({default}).", file=sys.stderr)
            return default
        with open(config_file, 'r') as f:
            config = json.load(f)
        keys = key.split('.')
        value = config
        for k in keys:
            value = value.get(k, default)
        if value is None:
            print(f"Warning: Key {key} not found in {config_file}. Using default ({default}).", file=sys.stderr)
            return default
        # Validate numeric values
        if key in ['logging.retention_days', 'logging.max_log_files']:
            if not isinstance(value, int) or value <= 0:
                print(f"Warning: Invalid {key} ({value}) in {config_file}. Using default ({default}).", file=sys.stderr)
                return default
        # Validate directory paths
        if key in ['logging.directory', 'output.directory']:
            if not isinstance(value, str) or not value.strip():
                print(f"Warning: Invalid {key} ({value}) in {config_file}. Using default ({default}).", file=sys.stderr)
                return default
        return value
    except json.JSONDecodeError as e:
        print(f"Warning: Invalid JSON in {config_file}: {e}. Using default for {key} ({default}).", file=sys.stderr)
        return default
    except Exception as e:
        print(f"Warning: Failed to parse {key} from {config_file}: {e}. Using default ({default}).", file=sys.stderr)
        return default

def download_data_file(output_filename):
    """
    Download a data file based on its output filename from config.json sources with retries.

    Args:
        output_filename (str): The output filename (e.g., 'cisa_kev.json').

    Returns:
        bool: True if download succeeds, False otherwise.
    """
    config_file = 'config.json'
    max_retries = 3
    retry_delay = 5  # seconds
    try:
        if not os.path.isfile(config_file):
            print(f"Error: {config_file} not found. Cannot download {output_filename}.", file=sys.stderr)
            return False
        if not os.access(config_file, os.R_OK):
            print(f"Error: Permission denied reading {config_file}. Cannot download {output_filename}.", file=sys.stderr)
            return False
        with open(config_file, 'r') as f:
            config = json.load(f)
        sources = [s for s in config.get('sources', []) if s.get('output') == output_filename and s.get('enabled', True)]
        if not sources:
            print(f"Error: No enabled source found for {output_filename} in {config_file}.", file=sys.stderr)
            return False
        for attempt in range(1, max_retries + 1):
            try:
                if download_data(sources):
                    return True
                else:
                    print(f"Attempt {attempt}/{max_retries} failed for {output_filename}: Invalid content or partial failure.", file=sys.stderr)
            except requests.RequestException as e:
                print(f"Attempt {attempt}/{max_retries} failed for {output_filename}: {e}", file=sys.stderr)
            if attempt < max_retries:
                print(f"Retrying in {retry_delay} seconds...", file=sys.stderr)
                time.sleep(retry_delay)
            else:
                print(f"Warning: Failed to download {output_filename} after {max_retries} attempts.", file=sys.stderr)
                print(f"URL: {sources[0].get('url', 'N/A')}", file=sys.stderr)
                print(f"Check logs/download.log for details or use a local file: cp /path/to/{output_filename} data/{output_filename}", file=sys.stderr)
                print(f"Update {config_file} with: \"url\": \"file:///path/to/{output_filename}\"", file=sys.stderr)
                return False
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in {config_file}: {e}. Cannot download {output_filename}.", file=sys.stderr)
        return False
    except PermissionError as e:
        print(f"Error: Permission denied reading {config_file}: {e}. Cannot download {output_filename}.", file=sys.stderr)
        return False
    except Exception as e:
        print(f"Error: Failed to process {config_file} for {output_filename}: {e}.", file=sys.stderr)
        return False

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Error: Usage: python3 parse_config.py <command> [args]", file=sys.stderr)
        sys.exit(1)
    
    command = sys.argv[1]
    if command == 'get':
        if len(sys.argv) != 4:
            print("Error: Usage: python3 parse_config.py get <key> <default>", file=sys.stderr)
            sys.exit(1)
        print(get_config_value(sys.argv[2], sys.argv[3]))
    elif command == 'download':
        if len(sys.argv) != 3:
            print("Error: Usage: python3 parse_config.py download <output_filename>", file=sys.stderr)
            sys.exit(1)
        sys.exit(0 if download_data_file(sys.argv[2]) else 1)
    else:
        print(f"Error: Unknown command {command}", file=sys.stderr)
        sys.exit(1)
