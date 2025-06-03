import json
import logging
import os
from collections import defaultdict

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def load_attack_mappings(data_dir):
    """Load ATT&CK to NIST control mappings."""
    attack_mapping_path = os.path.join(data_dir, "attack_mapping.json")
    try:
        with open(attack_mapping_path, "r") as f:
            mappings = json.load(f)
        logging.info(f"Loaded {len(mappings.get('mapping_objects', []))} ATT&CK technique mappings from {attack_mapping_path}")
        return mappings
    except Exception as e:
        logging.error(f"Failed to load attack mappings from {attack_mapping_path}: {e}")
        return {}

def normalize_control_id(control_id):
    """Normalize NIST control ID (e.g., AC-02 to AC-2)."""
    if not control_id:
        return control_id
    parts = control_id.split("-")
    if len(parts) == 2:
        prefix, num = parts
        return f"{prefix}-{int(num):d}"
    return control_id

def map_risks_to_controls(all_risks, data_dir):
    """Map risks to NIST controls and compute scores."""
    controls = defaultdict(lambda: {
        "max_exploitation": 0.0,
        "max_severity": 0.0,
        "applicability": 7.0,
        "total_score": 0.0,
        "title": "",
        "family_title": "Unknown",
        "risk_contexts": []
    })
    control_details = {}
    
    control_details_path = os.path.join(data_dir, "nist_controls.json")
    if os.path.exists(control_details_path):
        try:
            with open(control_details_path, "r") as f:
                control_details = json.load(f)
            logging.info(f"Loaded NIST control details from {control_details_path}")
        except Exception as e:
            logging.error(f"Failed to load NIST control details: {e}")
    else:
        logging.warning(f"NIST control details file {control_details_path} not found, using default values")
    
    for source, risks in all_risks.items():
        for risk in risks:
            for control_id in risk.get("mitigating_controls", []):
                normalized_id = normalize_control_id(control_id)
                controls[normalized_id]["max_exploitation"] = max(
                    controls[normalized_id]["max_exploitation"],
                    float(risk.get("exploitation_score", 0.0))  # Convert to float
                )
                controls[normalized_id]["max_severity"] = max(
                    controls[normalized_id]["max_severity"],
                    float(risk.get("impact_score", 0.0))  # Convert to float
                )
                if risk.get("risk_context"):
                    context_entry = {
                        "cve_id": risk.get("cve_id", ""),
                        "context": risk.get("risk_context", ""),
                        "source": source
                    }
                    if context_entry not in controls[normalized_id]["risk_contexts"]:
                        controls[normalized_id]["risk_contexts"].append(context_entry)
                details = control_details.get(normalized_id, {})
                controls[normalized_id]["title"] = details.get("title", normalized_id)
                controls[normalized_id]["family_title"] = details.get("family_title", "Unknown")
                if not details.get("family_title"):
                    logging.debug(f"No family_title found for control {normalized_id}, defaulting to 'Unknown'")
    
    return controls, control_details

def normalize_and_prioritize(controls, weights):
    """Normalize and prioritize controls based on scores."""
    prioritized = []
    for control_id, details in controls.items():
        total_score = (
            weights["exploitation"] * float(details["max_exploitation"]) +
            weights["severity"] * float(details["max_severity"]) +
            weights["applicability"] * float(details["applicability"])
        )
        details["total_score"] = total_score
        prioritized.append((control_id, details))
    
    prioritized.sort(key=lambda x: x[1]["total_score"], reverse=True)
    return prioritized
