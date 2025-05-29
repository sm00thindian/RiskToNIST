import argparse
import json
import logging
import os
from utils.download import download_datasets
from utils.parse import parse_all_datasets
from utils.map_risks import map_risks_to_controls, normalize_and_prioritize
from utils.output import write_outputs

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def load_config(config_path):
    """Load configuration from a JSON file.

    Args:
        config_path (str): Path to the configuration file.

    Returns:
        dict: Configuration dictionary.
    """
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
        logging.info(f"Loaded configuration from {config_path}")
        return config
    except Exception as e:
        logging.error(f"Failed to load config {config_path}: {e}")
        raise

def load_attack_mappings(data_dir):
    """Load ATT&CK mappings from utils.map_risks to pass to parsing.

    Args:
        data_dir (str): Directory containing attack_mapping.json.

    Returns:
        dict: ATT&CK technique to NIST control mappings.
    """
    from utils.map_risks import load_attack_mappings
    mappings = load_attack_mappings(data_dir)
    return mappings

def main(config_path, data_dir):
    """Main function to process risk data and generate prioritized controls.

    Args:
        config_path (str): Path to the configuration file.
        data_dir (str): Directory for data files.
    """
    # Load configuration
    config = load_config(config_path)
    
    # Download datasets
    logging.info("Starting dataset downloads")
    download_datasets(config, data_dir)
    
    # Load ATT&CK mappings for KEV cross-referencing
    attack_mappings = load_attack_mappings(data_dir)
    if not attack_mappings:
        logging.warning("No ATT&CK mappings loaded; KEV ATT&CK parsing may be limited")
    
    # Parse all datasets
    logging.info("Parsing datasets")
    all_risks = parse_all_datasets(data_dir, attack_mappings)
    
    # Map risks to controls
    logging.info("Mapping risks to NIST controls")
    controls, _ = map_risks_to_controls(all_risks, data_dir)
    
    # Normalize and prioritize controls
    weights = config.get("weights", {"exploitation": 0.4, "severity": 0.4, "applicability": 0.2})
    logging.info(f"Using weights: {weights}")
    prioritized_controls = normalize_and_prioritize(controls, weights)
    
    # Write outputs
    logging.info("Writing outputs")
    write_outputs(prioritized_controls, data_dir)
    
    logging.info("Processing complete")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process risk data and prioritize NIST controls")
    parser.add_argument("--config", default="config.json", help="Path to configuration file")
    parser.add_argument("--data_dir", default="data", help="Directory for data files")
    args = parser.parse_args()
    
    try:
        main(args.config, args.data_dir)
    except Exception as e:
        logging.error(f"Program failed: {e}")
        raise