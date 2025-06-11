# src/env/main.py
"""Main module to orchestrate the NIST 800-53 control prioritization workflow.

This script loads AWS and ATT&CK-to-NIST mapping data, identifies gaps, prioritizes
NIST controls based on risk, and exports results to CSV, JSON, and HTML formats.
"""
import os
import json
from data_loader import load_aws_data, load_attack_to_nist_mapping
from gap_identifier import identify_gaps
from risk_prioritizer import prioritize_controls
from exporter import export_to_csv, export_to_json, export_to_html

def main():
    """Main function to run the NIST control prioritization project."""
    # Get the directory of the current script (src/env/)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    # Construct paths relative to src/env/
    aws_file = os.path.join(script_dir, 'aws-12.12.2024_attack-16.1-enterprise.json')
    mapping_file = os.path.join(script_dir, 'attack_mapping.json')
    # Output directory in project root
    project_root = os.path.dirname(os.path.dirname(script_dir))
    output_dir = os.path.join(project_root, 'output')

    # Create output directory if it doesn't exist
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Load data
    aws_data = load_aws_data(aws_file)
    attack_to_nist = load_attack_to_nist_mapping(mapping_file)

    # Identify gaps and save to a file
    gaps = identify_gaps(aws_data, attack_to_nist)
    with open(os.path.join(output_dir, 'gaps.json'), 'w') as f:
        json.dump(list(gaps), f, indent=4)

    # Prioritize controls
    prioritized_controls = prioritize_controls(aws_data, attack_to_nist)

    # Export results
    export_to_csv(prioritized_controls, os.path.join(output_dir, 'controls.csv'))
    export_to_json(prioritized_controls, os.path.join(output_dir, 'controls.json'))
    export_to_html(prioritized_controls, os.path.join(output_dir, 'controls.html'))

if __name__ == '__main__':
    main()
