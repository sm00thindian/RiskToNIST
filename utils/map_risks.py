import json
import os
import requests
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def normalize_control_id(control_id):
    """Normalize control ID by removing leading zeros from the numeric part.

    Args:
        control_id (str): The control ID to normalize (e.g., 'AC-02', 'SI-2').

    Returns:
        str: Normalized control ID (e.g., 'AC-2', 'SI-2').
    """
    if '-' in control_id:
        family, num = control_id.split('-', 1)
        num = num.lstrip('0') or '0'
        return f"{family.upper()}-{num}"
    return control_id.upper()

def load_nist_controls():
    """Load NIST SP 800-53 controls from OSCAL JSON, including family info.

    Returns:
        dict: Dictionary of control IDs to details.
    """
    filepath = "mappings/nist_controls.json"
    url = "https://github.com/usnistgov/oscal-content/raw/refs/heads/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"
    
    if not os.path.exists(filepath) or os.path.getsize(filepath) == 0:
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            with open(filepath, "wb") as f:
                f.write(response.content)
            logging.info(f"Downloaded NIST controls to {filepath}")
        except requests.RequestException as e:
            logging.error(f"Failed to download NIST controls: {e}")
            return {}
    
    try:
        with open(filepath, "r") as f:
            data = json.load(f)
        controls = {}
        for group in data["catalog"]["groups"]:
            family_id = group["id"]
            family_title = group["title"]
            for control in group["controls"]:
                control_id = normalize_control_id(control["id"])
                controls[control_id] = {
                    "title": control["title"],
                    "family_id": family_id,
                    "family_title": family_title,
                    "applicability": 7.0,
                    "max_exploitation": 0.0,
                    "max_severity": 0.0
                }
        logging.info(f"Loaded {len(controls)} NIST controls")
        return controls
    except (KeyError, json.JSONDecodeError) as e:
        logging.error(f"Invalid OSCAL structure or JSON: {e}")
        return {}

def load_attack_mappings(data_dir="data"):
    """Load MITRE ATT&CK to NIST 800-53 mappings.

    Args:
        data_dir (str): Directory containing the attack_mapping.json file.

    Returns:
        dict: Dictionary mapping ATT&CK techniques to NIST control IDs.
    """
    filepath = os.path.join(data_dir, "attack_mapping.json")
    if not os.path.exists(filepath):
        logging.error(f"{filepath} not found, no ATT&CK mappings loaded.")
        return {}
    try:
        with open(filepath, "r") as f:
            data = json.load(f)
        logging.debug(f"Contents of {filepath}: {json.dumps(data, indent=2)[:1000]}...")
        mappings = {}
        if not isinstance(data.get("mapping_objects"), list):
            logging.error(f"Invalid structure in {filepath}: 'mapping_objects' key missing or not a list")
            return {}
        for item in data.get("mapping_objects", []):
            if not isinstance(item, dict):
                logging.warning(f"Skipping invalid item in {filepath}: {item}")
                continue
            if item.get("mapping_type") == "mitigates" and item.get("capability_id") and item.get("attack_object_id"):
                technique = item.get("attack_object_id")
                control_id = normalize_control_id(item.get("capability_id"))
                mappings.setdefault(technique, []).append(control_id)
        logging.info(f"Loaded {len(mappings)} ATT&CK technique mappings")
        return mappings
    except json.JSONDecodeError as e:
        logging.error(f"Error parsing {filepath}: {e}")
        return {}
    except Exception as e:
        logging.error(f"Unexpected error loading {filepath}: {e}")
        return {}

def map_risks_to_controls(all_risks, data_dir="data"):
    """Map risks from all sources to NIST controls, tracking max scores.

    Args:
        all_risks (dict): Dictionary of source names to lists of risks.
        data_dir (str): Directory containing data files.

    Returns:
        tuple: (controls, attack_mappings) Dictionary of controls and ATT&CK mappings.
    """
    controls = load_nist_controls()
    attack_mappings = load_attack_mappings(data_dir)
    
    for source_name, risks in all_risks.items():
        logging.info(f"Mapping {len(risks)} risks from {source_name}")
        for risk in risks:
            controls_to_map = risk["mitigating_controls"]
            # Enhance NVD, CISA KEV, KEV ATT&CK, and fallback with ATT&CK mappings
            if source_name in ["nvd_cve", "cisa_kev", "kev_attack", "fallback"] and attack_mappings:
                cwe = risk.get("cwe", "")
                if isinstance(cwe, str):
                    if "CWE-22" in cwe and "T1190" in attack_mappings:
                        controls_to_map.extend(attack_mappings["T1190"])  # Exploit Public-Facing App
                        logging.debug(f"Applied T1190 controls for CWE-22: {attack_mappings['T1190']}")
                    elif "CWE-79" in cwe and "T1566" in attack_mappings:
                        controls_to_map.extend(attack_mappings["T1566"])  # Phishing
                        logging.debug(f"Applied T1566 controls for CWE-79: {attack_mappings['T1566']}")
                    elif any(cwe_id in cwe for cwe_id in ["CWE-94", "CWE-288", "CWE-502", "CWE-78", "CWE-287"]) and "T1078" in attack_mappings:
                        controls_to_map.extend(attack_mappings["T1078"])  # Valid Accounts
                        logging.debug(f"Applied T1078 controls for CWE-94/288/502/78/287: {attack_mappings['T1078']}")
                    elif "CWE-416" in cwe and "T1203" in attack_mappings:
                        controls_to_map.extend(attack_mappings["T1203"])  # Exploitation