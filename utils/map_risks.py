"""Utility functions to map risks to NIST 800-53 controls and prioritize them."""

import json
import os
import requests
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def load_nist_controls():
    """Load NIST 800-53 controls from JSON file, downloading if not present.

    Returns:
        dict: Dictionary of control IDs to descriptions.
    """
    filepath = "mappings/nist_controls.json"
    primary_url = "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"
    fallback_url = "https://csrc.nist.gov/files/pubs/sp/800/53/r5/upd1/final/oscal/json/NIST_SP-800-53_rev5_catalog.json"

    # Download if file doesn't exist or is empty
    if not os.path.exists(filepath) or os.path.getsize(filepath) == 0:
        for url in [primary_url, fallback_url]:
            try:
                response = requests.get(url, timeout=10)
                response.raise_for_status()
                content = response.content
                # Verify content is valid JSON
                json.loads(content)
                with open(filepath, "wb") as f:
                    f.write(content)
                logging.info(f"Downloaded NIST controls to {filepath} from {url}")
                break
            except (requests.RequestException, json.JSONDecodeError) as e:
                logging.warning(f"Failed to download NIST controls from {url}: {e}")
                continue
        else:
            logging.error("All download attempts failed, creating default controls")
            default_controls = {
                "RA-5": "Vulnerability Scanning",
                "SI-2": "Flaw Remediation",
                "SI-4": "System Monitoring"
            }
            with open(filepath, "w") as f:
                json.dump({"catalog": {"controls": [{"id": k, "title": v} for k, v in default_controls.items()]}}, f)
            logging.info(f"Created default controls in {filepath}")

    # Load controls
    try:
        with open(filepath, "r") as f:
            content = f.read()
        if not content.strip():
            logging.error(f"{filepath} is empty, using default controls")
            default_controls = {
                "RA-5": "Vulnerability Scanning",
                "SI-2": "Flaw Remediation",
                "SI-4": "System Monitoring"
            }
            return default_controls
        data = json.loads(content)
        # Handle different possible keys for controls
        controls_list = data["catalog"].get("controls", data["catalog"].get("control", []))
        if not controls_list:
            logging.error("No controls found in catalog, using default controls")
            default_controls = {
                "RA-5": "Vulnerability Scanning",
                "SI-2": "Flaw Remediation",
                "SI-4": "System Monitoring"
            }
            return default_controls
        controls = {control["id"]: control["title"] for control in controls_list}
        logging.info(f"Loaded {len(controls)} NIST controls from {filepath}")
        return controls
    except json.JSONDecodeError as e:
        logging.error(f"Failed to parse {filepath}: {e}, using default controls")
        default_controls = {
            "RA-5": "Vulnerability Scanning",
            "SI-2": "Flaw Remediation",
            "SI-4": "System Monitoring"
        }
        return default_controls

def load_attack_mappings():
    """Load MITRE ATT&CK to NIST 800-53 mappings.

    Returns:
        dict: Dictionary mapping ATT&CK techniques to NIST controls.
    """
    filepath = "mappings/attack_to_nist.json"
    if not os.path.exists(filepath):
        url = "https://ctid.mitre.org/projects/nist-800-53-control-mappings/attack_to_nist.json"
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            with open(filepath, "wb") as f:
                f.write(response.content)
            logging.info(f"Downloaded ATT&CK mappings to {filepath}")
        except requests.RequestException as e:
            logging.warning(f"Failed to download ATT&CK mappings: {e}, using default mappings")
            return {}  # Empty mappings as fallback
    try:
        with open(filepath, "r") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        logging.warning(f"Failed to parse {filepath}: {e}, using default mappings")
        return {}

def map_risks_to_controls(risks):
    """Map risk indicators to NIST 800-53 controls.

    Args:
        risks (dict): Dictionary of risk indicators from each source.

    Returns:
        dict: Dictionary of controls with associated risks and scores.
    """
    controls = load_nist_controls()
    attack_mappings = load_attack_mappings()

    control_risks = {control_id: {"title": title, "risks": [], "score": 0.0}
                     for control_id, title in controls.items()}

    # Map NVD vulnerabilities
    for risk in risks["nvd"]:
        control_risks["RA-5"]["risks"].append(risk["cve"])
        control_risks["RA-5"]["score"] += risk["score"]

    # Map KEV vulnerabilities
    for risk in risks["kev"]:
        control_risks["SI-2"]["risks"].append(risk["cve"])
        control_risks["SI-2"]["score"] += risk["score"]

    # Map ATT&CK techniques
    for risk in risks["attack"]:
        technique = risk["technique"]
        if technique in attack_mappings:
            for control_id in attack_mappings[technique]:
                control_risks[control_id]["risks"].append(technique)
                control_risks[control_id]["score"] += risk["score"]

    return control_risks

def normalize_and_prioritize(controls):
    """Normalize risk scores and prioritize controls.

    Args:
        controls (dict): Dictionary of controls with risks and scores.

    Returns:
        list: Sorted list of controls by priority score.
    """
    max_score = max(control["score"] for control in controls.values() if control["score"] > 0) or 1
    for control in controls.values():
        control["score"] = (control["score"] / max_score) * 100  # Normalize to 0-100

    return sorted(controls.items(), key=lambda x: x[1]["score"], reverse=True)