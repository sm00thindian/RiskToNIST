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
            print(f"Warning: Key {key} not found in config.json. Using default ({default}).", file=sys.stderr)
            return default
        # Validate numeric values
        if key in ['logging.retention_days', 'logging.max_log_files']:
            if not isinstance(value, int) or value <= 0:
                print(f"Warning: Invalid {key} ({value}) in config.json. Using default ({default}).", file=sys.stderr)
                return default
        return value
    except FileNotFoundError:
        print(f"Warning: config.json not found. Using default for {key} ({default}).", file=sys.stderr)
        return default
    except json.JSONDecodeError as e:
        print(f"Warning: Invalid JSON in config.json: {e}. Using default for {key} ({default}).", file=sys.stderr)
        return default
    except Exception as e:
        print(f"Warning: Failed to parse {key} from config.json: {e}. Using default ({default}).", file=sys.stderr)
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
            print(f"Error: No source found for {output_filename} in config.json", file=sys.stderr)
            sys.exit(1)
        download_data(sources)
    except FileNotFoundError:
        print(f"Error: config.json not found. Cannot download {output_filename}.", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in config.json: {e}. Cannot download {output_filename}.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: Failed to download {output_filename}: {e}. Check download.log for details.", file=sys.stderr)
        print(f"For {output_filename}, consider using local files:", file=sys.stderr)
        print(f"  cp /path/to/{output_filename} data/{output_filename}", file=sys.stderr)
        print(f"Update config.json with: \"url\": \"file:///path/to/{output_filename}\"", file=sys.stderr)
        sys.exit(1)

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
        download_data_file(sys.argv[2])
    else:
        print(f"Error: Unknown command {command}", file=sys.stderr)
        sys.exit(1)
