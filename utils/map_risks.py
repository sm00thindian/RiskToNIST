"""Utility functions to map risks to NIST 800-53 controls and prioritize them."""

import json
import os

def load_nist_controls():
    """Load NIST 800-53 controls from JSON file.

    Returns:
        dict: Dictionary of control IDs to descriptions.
    """
    if not os.path.exists("mappings/nist_controls.json"):
        # Download NIST 800-53 OSCAL JSON (placeholder URL)
        import requests
        url = "https://csrc.nist.gov/files/pubs/sp/800/53/r5/upd1/final/oscal/json/NIST_SP-800-53_rev5_catalog.json"
        with open("mappings/nist_controls.json", "wb") as f:
            f.write(requests.get(url, timeout=10).content)
    
    with open("mappings/nist_controls.json", "r") as f:
        data = json.load(f)
    controls = {control["id"]: control["title"] for control in data["catalog"]["controls"]}
    return controls

def load_attack_mappings():
    """Load MITRE ATT&CK to NIST 800-53 mappings.

    Returns:
        dict: Dictionary mapping ATT&CK techniques to NIST controls.
    """
    if not os.path.exists("mappings/attack_to_nist.json"):
        # Placeholder: Download from CTID or use a predefined mapping
        url = "https://ctid.mitre.org/projects/nist-800-53-control-mappings/attack_to_nist.json"
        import requests
        with open("mappings/attack_to_nist.json", "wb") as f:
            f.write(requests.get(url, timeout=10).content)
    
    with open("mappings/attack_to_nist.json", "r") as f:
        return json.load(f)

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

    # Map CIC and Stratosphere network risks
    for risk in risks["cic"] + risks["stratosphere"]:
        control_risks["SI-4"]["risks"].append(risk["attack"])
        control_risks["SI-4"]["score"] += risk["score"]

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
