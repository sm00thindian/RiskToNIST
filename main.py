import argparse
import json
import logging
import os
from utils.download import download_datasets
from utils.parse import parse_all_datasets
from utils.map_risks import map_risks_to_controls, normalize_and_prioritize
from utils.output import write_outputs

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def load_api_keys():
    """Load API keys from api_keys.json and set environment variables."""
    api_keys_path = "api_keys.json"
    try:
        if os.path.exists(api_keys_path):
            with open(api_keys_path, 'r') as f:
                api_keys = json.load(f)
            nvd_api_key = api_keys.get('NVD_API_KEY')
            if nvd_api_key:
                os.environ['NVD_API_KEY'] = nvd_api_key
                logging.info("Loaded NVD_API_KEY from api_keys.json")
            else:
                logging.warning("NVD_API_KEY not found in api_keys.json")
        else:
            logging.warning(f"api_keys.json not found at {api_keys_path}")
    except Exception as e:
        logging.error(f"Failed to load api_keys.json: {e}")

def load_config(config_path):
    """Load configuration from a JSON file."""
    try:
        logging.info(f"Loading configuration from {config_path}")
        with open(config_path, 'r') as f:
            config = json.load(f)
        logging.info(f"Successfully loaded configuration")
        return config
    except Exception as e:
        logging.error(f"Failed to load config {config_path}: {e}")
        raise

def load_attack_mappings(data_dir):
    """Load ATT&CK mappings from utils.map_risks."""
    from utils.map_risks import load_attack_mappings
    logging.info(f"Loading ATT&CK mappings from {data_dir}")
    mappings = load_attack_mappings(data_dir)
    logging.info(f"Loaded {len(mappings.get('mapping_objects', []))} ATT&CK mappings")
    return mappings

def main(config_path, data_dir, force_refresh=False):
    """Main function to process risk data and generate prioritized controls."""
    # Load API keys first
    load_api_keys()
    
    config = load_config(config_path)
    
    logging.info("Starting dataset downloads")
    download_datasets(config, data_dir, force_refresh)
    logging.info("Completed dataset downloads")
    
    attack_mappings = load_attack_mappings(data_dir)
    if not attack_mappings:
        logging.warning("No ATT&CK mappings loaded; KEV ATT&CK parsing may be limited")
    
    logging.info("Starting dataset parsing")
    all_risks = parse_all_datasets(data_dir, attack_mappings)
    logging.info(f"Parsed risks from {len(all_risks)} sources")
    
    logging.info("Mapping risks to NIST controls")
    controls, _ = map_risks_to_controls(all_risks, data_dir)
    logging.info(f"Mapped {len(controls)} controls")
    
    weights = config.get("weights", {"exploitation": 0.4, "severity": 0.4, "applicability": 0.2})
    logging.info(f"Normalizing and prioritizing with weights: {weights}")
    prioritized_controls = normalize_and_prioritize(controls, weights)
    logging.info(f"Prioritized {len(prioritized_controls)} controls")
    
    logging.info("Writing outputs")
    write_outputs(prioritized_controls, data_dir)
    logging.info("Completed writing outputs")
    
    logging.info("Processing complete")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process risk data and prioritize NIST controls")
    parser.add_argument("--config", default="config.json", help="Path to configuration file")
    parser.add_argument("--data_dir", default="data", help="Directory for data files")
    parser.add_argument("--force-refresh", action="store_true", help="Force refresh of downloaded files")
    args = parser.parse_args()
    
    try:
        main(args.config, args.data_dir, args.force_refresh)
    except Exception as e:
        logging.error(f"Program failed: {e}")
        raise
