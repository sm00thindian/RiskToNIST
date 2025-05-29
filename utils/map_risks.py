import json
import os
import requests
import logging

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
                control_id = control["id"]
                controls[control_id] = {
                    "title": control["title"],
                    "family_id": family_id,
                    "family_title": family_title,
                    "applicability": 7.0,
                    "max_exploitation": 0.0,
                    "max_severity": 0.0
                }
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
        print(f"Warning: {filepath} not found, skipping ATT&CK mappings.")
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
                        mappings.setdefault(technique, []).append(control_id.replace("control-", ""))
        return mappings
    except json.JSONDecodeError as e:
        print(f"Error parsing {filepath}: {e}")
        return {}

def map_risks_to_controls(all_risks, data_dir="data"):
    """Map risks from all sources to NIST controls, tracking max scores.

    Args:
        all_risks (dict): Dictionary of source names to lists of risks.
        data_dir (str): Directory containing data files.

    Returns:
        dict: Dictionary of controls with risk scores.
    """
    controls = load_nist_controls()
    attack_mappings = load_attack_mappings(data_dir)
    
    for source_name, risks in all_risks.items():
        for risk in risks:
            controls_to_map = risk["mitigating_controls"]
            # Enhance with ATT&CK mappings for NVD CVEs
            if source_name == "nvd_cve" and attack_mappings:
                # Placeholder: Assume CVE descriptions could map to techniques
                # For simplicity, assign a default technique score if no direct mapping
                for technique, mapped_controls in attack_mappings.items():
                    controls_to_map.extend(mapped_controls)
                    controls_to_map = list(set(controls_to_map))  # Remove duplicates
            
            for control_id in controls_to_map:
                if control_id in controls:
                    controls[control_id]["max_exploitation"] = max(
                        controls[control_id]["max_exploitation"],
                        risk["exploitation_score"]
                    )
                    controls[control_id]["max_severity"] = max(
                        controls[control_id]["max_severity"],
                        risk["impact_score"]
                    )
    
    return controls

def normalize_and_prioritize(controls):
    """Calculate total scores and prioritize top 50 controls.

    Args:
        controls (dict): Dictionary of controls with risk scores.

    Returns:
        list: Top 50 controls sorted by total score.
    """
    for control in controls.values():
        control["total_score"] = (
            0.4 * control["max_exploitation"] +  # 40% Exploitation Frequency
            0.4 * control["max_severity"] +      # 40% Severity/Impact
            0.2 * control["applicability"]       # 20% Applicability
        )
    return sorted(controls.items(), key=lambda x: x[1]["total_score"], reverse=True)[:50]