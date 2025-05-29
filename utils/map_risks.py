import json
import os
import requests
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

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
                control_id = control["id"].upper()  # Normalize to uppercase
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
        logging.warning(f"{filepath} not found, skipping ATT&CK mappings.")
        return {}
    try:
        with open(filepath, "r") as f:
            data = json.load(f)
        mappings = {}
        for item in data.get("objects", []):
            if item.get("type") == "relationship" and item.get("relationship_type") == "mitigates":
                technique_id = item.get("source_ref", "").split("--")[0]
                control_id = item.get("target_ref", "").split("--")[0]
                if technique_id.startswith("attack-pattern") and control_id.startswith("control"):
                    technique = item.get("external_references", [{}])[0].get("external_id", "")
                    if technique:
                        mappings.setdefault(technique, []).append(control_id.replace("control-", "").upper())
        logging.info(f"Loaded {len(mappings)} ATT&CK technique mappings")
        return mappings
    except json.JSONDecodeError as e:
        logging.error(f"Error parsing {filepath}: {e}")
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
            # Enhance NVD CVEs with ATT&CK mappings
            if source_name == "nvd_cve" and attack_mappings:
                # Apply scores to controls for common techniques
                common_techniques = ["T1190", "T1566", "T1078"]  # Exploit Public-Facing App, Phishing, Valid Accounts
                for technique in common_techniques:
                    if technique in attack_mappings:
                        controls_to_map.extend(attack_mappings[technique])
                        logging.debug(f"Applied technique {technique} controls: {attack_mappings[technique]}")
                controls_to_map = list(set(controls_to_map))  # Remove duplicates
            
            for control_id in controls_to_map:
                control_id = control_id.upper()  # Ensure uppercase
                if control_id in controls:
                    controls[control_id]["max_exploitation"] = max(
                        controls[control_id]["max_exploitation"],
                        risk["exploitation_score"]
                    )
                    controls[control_id]["max_severity"] = max(
                        controls[control_id]["max_severity"],
                        risk["impact_score"]
                    )
                    logging.debug(f"Updated {control_id}: max_exploitation={controls[control_id]['max_exploitation']}, max_severity={controls[control_id]['max_severity']}")
                else:
                    logging.warning(f"Control {control_id} not found in NIST catalog")
    
    # Log controls with non-zero scores
    non_zero_controls = [cid for cid, data in controls.items() if data["max_exploitation"] > 0 or data["max_severity"] > 0]
    logging.info(f"Controls with non-zero scores: {len(non_zero_controls)} ({', '.join(non_zero_controls)})")
    return controls, attack_mappings

def normalize_and_prioritize(controls, weights):
    """Calculate total scores and prioritize top 50 controls using configurable weights.

    Args:
        controls (dict): Dictionary of controls with risk scores.
        weights (dict): Dictionary with 'exploitation', 'severity', and 'applicability' weights.

    Returns:
        list: Top 50 controls sorted by total score.
    """
    # Validate weights
    total_weight = sum(weights.values())
    if abs(total_weight - 1.0) > 0.01:
        logging.error(f"Weights sum to {total_weight}, must sum to 1.0")
        raise ValueError("Weights must sum to 1.0")
    
    logging.info(f"Using weights: exploitation={weights['exploitation']}, severity={weights['severity']}, applicability={weights['applicability']}")
    
    for control_id, control in controls.items():
        control["total_score"] = (
            weights["exploitation"] * control["max_exploitation"] +
            weights["severity"] * control["max_severity"] +
            weights["applicability"] * control["applicability"]
        )
        logging.debug(f"Control {control_id}: total_score={control['total_score']}")
    prioritized = sorted(controls.items(), key=lambda x: x[1]["total_score"], reverse=True)[:50]
    logging.info(f"Prioritized {len(prioritized)} controls")
    return prioritized