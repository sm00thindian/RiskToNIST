"""
utils/parse_config.py: Utility script to parse config.json for RiskToNist project.
Provides functions to read configuration values and download data files.
"""

import json
import sys
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
    try:
        with open('config.json', 'r') as f:
            config = json.load(f)
        keys = key.split('.')
        value = config
        for k in keys:
            value = value.get(k, default)
        if value is None:
            print(f"Warning: Key {key} not found in config.json. Using default ({default}).")
            return default
        return value
    except Exception as e:
        print(f"Warning: Failed to parse {key} from config.json: {e}. Using default ({default}).")
        return default

def download_data_file(output_filename):
    """
    Download a data file based on its output filename from config.json sources.

    Args:
        output_filename (str): The output filename (e.g., 'cisa_kev.json').

    Returns:
        None

    Raises:
        SystemExit: If no source is found or download fails.
    """
    try:
        with open('config.json', 'r') as f:
            config = json.load(f)
        sources = [s for s in config.get('sources', []) if s.get('output') == output_filename]
        if not sources:
            print(f"Error: No source found for {output_filename} in config.json")
            sys.exit(1)
        download_data(sources)
    except Exception as e:
        print(f"Error: Failed to download {output_filename}. Check download.log for details.")
        print(f"For {output_filename}, consider using local files:")
        print(f"  cp /path/to/{output_filename} data/{output_filename}")
        print(f"Update config.json with: \"url\": \"file:///path/to/{output_filename}\"")
        sys.exit(1)

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Error: Usage: python3 parse_config.py <command> [args]")
        sys.exit(1)
    
    command = sys.argv[1]
    if command == 'get':
        if len(sys.argv) != 4:
            print("Error: Usage: python3 parse_config.py get <key> <default>")
            sys.exit(1)
        print(get_config_value(sys.argv[2], sys.argv[3]))
    elif command == 'download':
        if len(sys.argv) != 3:
            print("Error: Usage: python3 parse_config.py download <output_filename>")
            sys.exit(1)
        download_data_file(sys.argv[2])
    else:
        print(f"Error: Unknown command {command}")
        sys.exit(1)
