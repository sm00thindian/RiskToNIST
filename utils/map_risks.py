import json
import os
import requests
import logging

def load_nist_controls():
    """Load NIST SP 800-53 controls from OSCAL JSON, including family info."""
    filepath = "mappings/nist_controls.json"
    url = "https://github.com/usnistgov/oscal-content/raw/refs/heads/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"
    
    # Download catalog if not present or empty
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
                    "applicability": 7.0,  # Default applicability
                    "max_exploitation": 0.0,
                    "max_severity": 0.0
                }
        return controls
    except (KeyError, json.JSONDecodeError) as e:
        logging.error(f"Invalid OSCAL structure or JSON: {e}")
        return {}

def map_risks_to_controls(all_risks):
    """Map risks from all sources to NIST controls, tracking max scores."""
    controls = load_nist_controls()
    for source_risks in all_risks.values():
        for risk in source_risks:
            for control_id in risk["mitigating_controls"]:
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
    """Calculate total scores and prioritize top 50 controls."""
    for control in controls.values():
        control["total_score"] = (
            0.4 * control["max_exploitation"] +  # 40% Exploitation Frequency
            0.4 * control["max_severity"] +      # 40% Severity/Impact
            0.2 * control["applicability"]       # 20% Applicability
        )
    return sorted(controls.items(), key=lambda x: x[1]["total_score"], reverse=True)[:50]