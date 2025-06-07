import json
import logging
import os
from collections import defaultdict

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def load_attack_mappings(data_dir):
    """Load ATT&CK to NIST control mappings from attack_mapping.json.

    Args:
        data_dir (str): Directory containing the mappings file.

    Returns:
        dict: ATT&CK mappings dictionary.
    """
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
    """Normalize NIST control ID (e.g., AC-02 to AC-2).

    Args:
        control_id (str): Control ID to normalize.

    Returns:
        str: Normalized control ID.
    """
    if not control_id:
        return control_id
    parts = control_id.split("-")
    if len(parts) == 2:
        prefix, num = parts
        try:
            return f"{prefix}-{int(num):d}"
        except ValueError:
            return control_id
    return control_id

def map_risks_to_controls(all_risks, data_dir):
    """Map risks to NIST controls and compute scores, ensuring diverse risk contexts.

    Args:
        all_risks (dict): Dictionary of risks by source.
        data_dir (str): Directory containing control details.

    Returns:
        tuple: (controls dict, control details dict)
    """
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
    cve_control_mappings = {}  # Track CVEs mapped to controls to avoid repetition

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

    if not isinstance(all_risks, dict) or not all_risks:
        logging.info("No valid risks provided; returning empty controls dictionary.")
        return controls, control_details

    for source, risks in all_risks.items():
        for risk in risks:
            cve_id = risk.get("cve_id", "")
            if not cve_id:
                continue
            for control_id in risk.get("mitigating_controls", []):
                normalized_id = normalize_control_id(control_id)
                if cve_id in cve_control_mappings and normalized_id in cve_control_mappings[cve_id]:
                    logging.debug(f"Skipping duplicate mapping of CVE {cve_id} to control {normalized_id}")
                    continue
                cve_control_mappings.setdefault(cve_id, set()).add(normalized_id)
                controls[normalized_id]["max_exploitation"] = max(
                    controls[normalized_id]["max_exploitation"],
                    float(risk.get("exploitation_score", 0.0))
                )
                controls[normalized_id]["max_severity"] = max(
                    controls[normalized_id]["max_severity"],
                    float(risk.get("impact_score", 0.0))
                )
                context_entry = {
                    "cve_id": cve_id,
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

    unmapped_techniques = set()
    for source, risks in all_risks.items():
        for risk in risks:
            if not risk.get("mitigating_controls"):
                logging.warning(f"No controls mapped for risk {risk.get('cve_id', 'unknown')} from source {source}")
                unmapped_techniques.add(risk.get('cwe', 'unknown'))

    if unmapped_techniques:
        logging.info(f"Unmapped techniques/CWEs: {', '.join(unmapped_techniques)}")

    return controls, control_details

def normalize_and_prioritize(controls, weights):
    """Normalize and prioritize controls based on scores.

    Args:
        controls (dict): Dictionary of controls with risk data.
        weights (dict): Weighting factors for scoring.

    Returns:
        list: Sorted list of (control_id, details) tuples.
    """
    prioritized = []
    max_exploitation = max((details["max_exploitation"] for details in controls.values()), default=1.0)
    max_severity = max((details["max_severity"] for details in controls.values()), default=1.0)
    max_applicability = max((details["applicability"] for details in controls.values()), default=1.0)

    for control_id, details in controls.items():
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
