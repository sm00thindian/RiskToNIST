#!/usr/bin/env python3
"""Main script to run the RiskToNIST project for NIST 800-53 control prioritization.

This script orchestrates the download, parsing, mapping, prioritization, and output generation
of risk data to prioritize the top 50 NIST 800-53 controls based on a scoring rubric.
"""

import os
import sys
import time
import threading
import argparse
from utils.download import download_datasets
from utils.parse import parse_all_datasets
from utils.map_risks import map_risks_to_controls, normalize_and_prioritize, load_attack_mappings
from utils.output import generate_outputs

def progress_wheel(stop_event):
    """Display a rotating progress wheel until stop_event is set.

    Args:
        stop_event (threading.Event): Event to signal when to stop the wheel.
    """
    chars = ['|', '/', '-', '\\']
    i = 0
    while not stop_event.is_set():
        sys.stdout.write(f'\rDownloading datasets... {chars[i % 4]}')
        sys.stdout.flush()
        i += 1
        time.sleep(0.2)
    sys.stdout.write('\rDownloading datasets... Done\n')
    sys.stdout.flush()

def main():
    """Execute the RiskToNIST workflow with configurable input directory."""
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Prioritize NIST 800-53 controls based on risk data.")
    parser.add_argument("--config", default="config.json", help="Path to the configuration file")
    parser.add_argument("--data_dir", default="data", help="Directory for downloaded and parsed data")
    args = parser.parse_args()

    # Ensure directories exist
    os.makedirs(args.data_dir, exist_ok=True)
    os.makedirs("mappings", exist_ok=True)
    os.makedirs("outputs", exist_ok=True)
    os.makedirs("templates", exist_ok=True)

    # Verify config file exists
    if not os.path.exists(args.config):
        print(f"Error: Configuration file {args.config} not found.")
        sys.exit(1)

    # Download datasets with progress wheel
    print("Starting dataset download...")
    stop_event = threading.Event()
    wheel_thread = threading.Thread(target=progress_wheel, args=(stop_event,))
    wheel_thread.start()
    try:
        download_datasets(config_path=args.config, data_dir=args.data_dir)
    except Exception as e:
        print(f"Error during download: {e}")
        stop_event.set()
        wheel_thread.join()
        sys.exit(1)
    finally:
        stop_event.set()
        wheel_thread.join()

    # Parse datasets to extract risk indicators
    print("Parsing datasets...")
    try:
        all_risks = parse_all_datasets(data_dir=args.data_dir)
        if not any(all_risks.values()):
            print("Error: No valid risk data parsed from CSVs or NVD.")
            sys.exit(1)
    except Exception as e:
        print(f"Error during parsing: {e}")
        sys.exit(1)

    # Map risks to NIST 800-53 controls and prioritize
    print("Mapping risks to controls and prioritizing...")
    try:
        attack_mappings = load_attack_mappings(data_dir=args.data_dir)
        controls = map_risks_to_controls(all_risks, data_dir=args.data_dir)
        prioritized_controls = normalize_and_prioritize(controls)
    except Exception as e:
        print(f"Error during mapping or prioritization: {e}")
        sys.exit(1)

    # Generate outputs
    print("Generating outputs...")
    try:
        generate_outputs(prioritized_controls, attack_mappings=attack_mappings)
    except Exception as e:
        print(f"Error during output generation: {e}")
        sys.exit(1)

    print("Process complete. Outputs are in the 'outputs/' directory:")
    print("- JSON: outputs/controls.json")
    print("- CSV: outputs/top_50_controls.csv")
    print("- HTML: outputs/controls.html (open in a browser)")
    print("- ATT&CK Mappings: outputs/attack_mappings.json")

if __name__ == "__main__":
    main()