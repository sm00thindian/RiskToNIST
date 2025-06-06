import os
import logging

def parse_all_datasets(data_dir, attack_mappings, config):
    """Parse all enabled datasets and return a dictionary of risks by source."""
    all_risks = {}
    
    for source in config.get("sources", []):
        name = source.get("name", "")
        enabled = source.get("enabled", True)
        output_file = source.get("output", "")
        
        if not enabled:
            logging.info(f"Skipping disabled source: {name}")
            continue
        
        if name == "CISA KEV":
            file_path = os.path.join(data_dir, output_file)
            if os.path.exists(file_path):
                all_risks["cisa_kev"] = parse_cisa_kev(file_path)
        elif name == "NVD CVE":
            file_path = os.path.join(data_dir, output_file)
            if os.path.exists(file_path):
                all_risks["nvd_cve"] = parse_nvd_cve(file_path)
        elif name == "KEV ATTACK Mapping":
            file_path = os.path.join(data_dir, output_file)
            if os.path.exists(file_path):
                all_risks["kev_attack"] = parse_kev_attack_mapping(file_path, attack_mappings)
    
    return all_risks

def parse_cisa_kev(file_path):
    # Placeholder for CISA KEV parsing logic
    return {}

def parse_nvd_cve(file_path):
    # Placeholder for NVD CVE parsing logic
    return {}

def parse_kev_attack_mapping(file_path, attack_mappings):
    # Placeholder for KEV ATTACK mapping parsing logic
    return {}
