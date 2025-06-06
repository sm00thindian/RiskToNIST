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
    
    # Handle case where all_risks is empty or not a dictionary
    if not isinstance(all_risks, dict) or not all_risks:
        logging.info("No valid risks provided; returning empty controls dictionary.")
        return controls, control_details
    
    for source, risks in all_risks.items():
        for risk in risks:
            for control_id in risk.get("mitigating_controls", []):
                normalized_id = normalize_control_id(control_id)
                controls[normalized_id]["max_exploitation"] = max(
                    controls[normalized_id]["max_exploitation"],
                    float(risk.get("exploitation_score", 0.0))
                )
                controls[normalized_id]["max_severity"] = max(
                    controls[normalized_id]["max_severity"],
                    float(risk.get("impact_score", 0.0))
                )
                if risk.get("risk_context"):
                    context_entry = {
                        "cve_id": risk.get("cve_id", ""),
                        "context": risk.get("risk_context", ""),
                        "source": source,
                        "exploitation_score": float(risk.get("exploitation_score", 0.0)),
                        "impact_score": float(risk.get("impact_score", 0.0)),
                        "cwe": risk.get("cwe", ""),
                        "exploit_maturity": risk.get("exploit_maturity", "UNREPORTED"),
                        "published_date": risk.get("published_date", None)
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
    # Find max values for normalization
    max_exploitation = max((details["max_exploitation"] for details in controls.values()), default=1.0)
    max_severity = max((details["max_severity"] for details in controls.values()), default=1.0)
    max_applicability = max((details["applicability"] for details in controls.values()), default=1.0)
    
    for control_id, details in controls.items():
        # Normalize scores to 0-10 scale
        norm_exploitation = (details["max_exploitation"] / max_exploitation * 10.0) if max_exploitation > 0 else 0.0
        norm_severity = (details["max_severity"] / max_severity * 10.0) if max_severity > 0 else 0.0
        norm_applicability = (details["applicability"] / max_applicability * 10.0) if max_applicability > 0 else 0.0
        total_score = (
            weights["exploitation"] * norm_exploitation +
            weights["severity"] * norm_severity +
            weights["applicability"] * norm_applicability
        )
        details["total_score"] = round(total_score, 2)
        prioritized.append((control_id, details))
    
    prioritized.sort(key=lambda x: x[1]["total_score"], reverse=True)
    return prioritized
