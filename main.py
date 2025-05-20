#!/usr/bin/env python3
"""Main script to run the RiskToNIST project."""

import os
import sys
from utils.download import download_datasets
from utils.parse import parse_all_datasets
from utils.map_risks import map_risks_to_controls, normalize_and_prioritize
from utils.output import generate_outputs

def main():
    """Execute the RiskToNIST workflow."""
    # Ensure directories exist
    os.makedirs("data", exist_ok=True)
    os.makedirs("mappings", exist_ok=True)
    os.makedirs("outputs", exist_ok=True)

    # Download datasets
    print("Downloading datasets...")
    download_datasets()

    # Parse datasets to extract risk indicators
    print("Parsing datasets...")
    risks = parse_all_datasets()

    # Map risks to NIST 800-53 controls and prioritize
    print("Mapping risks to controls and prioritizing...")
    controls = map_risks_to_controls(risks)
    prioritized_controls = normalize_and_prioritize(controls)

    # Generate outputs
    print("Generating outputs...")
    generate_outputs(prioritized_controls)

    print("Process complete. Outputs are in the 'outputs/' directory.")

if __name__ == "__main__":
    main()
