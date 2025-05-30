import json
import logging
import os
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def parse_cisa_kev(file_path):
    """Parse CISA KEV CSV file and return a list of risks.

    Args:
        file_path (str): Path to the CISA KEV CSV file.

    Returns:
        list: List of risk dictionaries.
    """
    import pandas as pd
    try:
        logging.debug(f"Attempting to parse CISA KEV file: {file_path}")
        df = pd.read_csv(file_path)
        logging.debug(f"Successfully loaded CISA KEV with {len(df)} entries")
        risks = []
        for _, row in df.iterrows():
            cve_id = row.get("cveID", "")
            if not cve_id:
                continue
            cwe_id = ""  # CISA KEV does not provide CWE
            risks.append({
                "mitigating_controls": ["SI-2", "RA-5", "SC-7"],  # Default controls
                "exploitation_score": 10.0,  # High score for known exploited
                "impact_score": 10.0,
                "cwe": cwe_id,
                "cve_id": cve_id,
                "risk_context": f"CISA KEV: {row.get('vulnerabilityName', '')}"
            })
        logging.info(f"Parsed {len(risks)} risks from {file_path}")
        return risks
    except Exception as e:
        logging.error(f"Failed to parse CISA KEV file {file_path}: {e}")
        return []

def parse_nvd_cve(file_path, schema_path=None):
    """Parse NVD CVE JSON file and return a list of risks after schema validation.

    Args:
        file_path (str): Path to the NVD CVE JSON file.
        schema_path (str, optional): Path to the schema file for validation.

    Returns:
        list: List of risk dictionaries.
    """
    from schema import validate_json
    try:
        logging.debug(f"Attempting to parse NVD CVE file: {file_path}")
        with open(file_path, "r") as f:
            data = json.load(f)
        
        # Validate against schema if provided
        if schema_path:
            logging.debug(f"Validating NVD CVE data against schema: {schema_path}")
            validate_json(data, schema_path)
        
        risks = []
        for item in data.get("CVE_Items", []):
            cve_id = item.get("cve", {}).get("CVE_data_meta", {}).get("ID", "")
            if not cve_id:
                continue
            cwe_id = ""
            for problem in item.get("cve", {}).get("problemtype", {}).get("problemtype_data", []):
                for desc in problem.get("description", []):
                    if desc.get("value", "").startswith("CWE-"):
                        cwe_id = desc.get("value", "")
                        break
                if cwe_id:
                    break
            cvss_v3 = item.get("impact", {}).get("baseMetricV3", {}).get("cvssV3", {})
            base_score = cvss_v3.get("baseScore", 0.0)
            risks.append({
                "mitigating_controls": ["SI-2", "RA-5"],  # Default controls
                "exploitation_score": base_score,
                "impact_score": base_score,
                "cwe": cwe_id,
                "cve_id": cve_id,
                "risk_context": item.get("cve", {}).get("description", {}).get("description_data", [{}])[0].get("value", "")
            })
        logging.info(f"Parsed {len(risks)} risks from {file_path}")
        return risks
    except Exception as e:
        logging.error(f"Failed to parse NVD CVE file {file_path}: {e}")
        return []

def parse_kev_attack_mapping(json_path, attack_mappings):
    """Parse KEV to ATT&CK mapping JSON file and return a list of risks.

    Args:
        json_path (str): Path to the KEV to ATT&CK mapping JSON file.
        attack_mappings (dict): Dictionary of ATT&CK to NIST control mappings.

    Returns:
        list: List of risk dictionaries.
    """
    try:
        logging.debug(f"Attempting to parse KEV ATT&CK mapping file: {json_path}")
        with open(json_path, "r") as f:
            data = json.load(f)
        risks = []
        capability_scores = {
            "code_execution": 10.0,
            "command_injection": 10.0,
            "untrusted_data": 9.0,
            "buffer_overflow": 9.0,
            "use_after_free": 9.0,
            "dir_traversal": 8.0,
            "input_validation": 8.0,
            "auth_bypass": 8.0,
            "priv_escalation": 8.0,
            "other": 7.0
        }
        for item in data.get("mapping_objects", []):
            cve_id = item.get("capability_id", "")
            technique_id = item.get("attack_object_id", "")
            capability_group = item.get("capability_group", "other")
            if not cve_id or not technique_id:
                continue
            controls = []
            for mapping in attack_mappings.get("mapping_objects", []):
                if mapping.get("attack_object_id") == technique_id:
                    controls.append(mapping.get("capability_id"))
            if not controls:
                logging.warning(f"No NIST controls mapped for technique {technique_id} in CVE {cve_id}")
                controls = ["SI-2"]  # Fallback control
            score = capability_scores.get(capability_group, 7.0)
            risks.append({
                "mitigating_controls": controls,
                "exploitation_score": score,
                "impact_score": score,
                "cwe": "",
                "cve_id": cve_id,
                "risk_context": item.get("comments", "")
            })
        logging.info(f"Parsed {len(risks)} risks from {json_path}")
        return risks
    except Exception as e:
        logging.error(f"Failed to parse KEV ATT&CK mapping file {json_path}: {e}")
        return []

def parse_all_datasets(data_dir, attack_mappings):
    """Parse all datasets and return a dictionary of risks by source.

    Args:
        data_dir (str): Directory containing data files.
        attack_mappings (dict): Dictionary of ATT&CK to NIST control mappings.

    Returns:
        dict: Dictionary with source names as keys and lists of risks as values.
    """
    all_risks = {}
    
    # Parse CISA KEV
    cisa_kev_path = os.path.join(data_dir, "cisa_kev.csv")
    if os.path.exists(cisa_kev_path):
        all_risks["cisa_kev"] = parse_cisa_kev(cisa_kev_path)
    
    # Parse NVD CVE
    for file_name in os.listdir(data_dir):
        if file_name.startswith("nvdcve-1.1-") and file_name.endswith(".json"):
            nvd_path = os.path.join(data_dir, file_name)
            # Pass schema path for NVD CVE validation
            schema_path = os.path.join(data_dir, "nvd_cve_schema.json")
            all_risks[f"nvd_{file_name}"] = parse_nvd_cve(nvd_path, schema_path if os.path.exists(schema_path) else None)
    
    # Parse KEV ATT&CK Mapping
    kev_attack_path = os.path.join(data_dir, "kev_attack_mapping.json")
    if os.path.exists(kev_attack_path):
        all_risks["kev_attack"] = parse_kev_attack_mapping(kev_attack_path, attack_mappings)
    
    # Fallback data
    fallback_risks = [
        {"mitigating_controls": ["AC-2"], "exploitation_score": 8.0, "impact_score": 8.0, "cwe": "", "cve_id": "", "risk_context": "Default access control risk"},
        {"mitigating_controls": ["AT-2"], "exploitation_score": 6.0, "impact_score": 6.0, "cwe": "", "cve_id": "", "risk_context": "Training deficiency risk"},
        {"mitigating_controls": ["CM-6"], "exploitation_score": 6.0, "impact_score": 6.0, "cwe": "", "cve_id": "", "risk_context": "Configuration management risk"},
        {"mitigating_controls": ["IA-2"], "exploitation_score": 7.0, "impact_score": 7.0, "cwe": "", "cwe_id": "", "risk_context": "Identification and authentication risk"},
        {"mitigating_controls": ["IA-5"], "exploitation_score": 7.0, "impact_score": 7.0, "cwe": "", "cve_id": "", "risk_context": "Authentication management risk"},
        {"mitigating_controls": ["RA-5"], "exploitation_score": 8.0, "impact_score": 8.0, "cwe": "", "cve_id": "", "risk_context": "Vulnerability scanning risk"},
        {"mitigating_controls": ["SC-7"], "exploitation_score": 8.0, "impact_score": 8.0, "cwe": "", "cve_id": "", "risk_context": "Boundary protection risk"},
        {"mitigating_controls": ["SC-8"], "exploitation_score": 6.0, "impact_score": 6.0, "cwe": "", "cve_id": "", "risk_context": "Transmission confidentiality risk"},
        {"mitigating_controls": ["SI-2"], "exploitation_score": 8.0, "impact_score": 8.0, "cwe": "", "cve_id": "", "risk_context": "Flaw remediation risk"},
        {"mitigating_controls": ["SI-10"], "exploitation_score": 6.0, "impact_score": 6.0, "cwe": "", "cve_id": "", "risk_context": "Input validation risk"},
        {"mitigating_controls": ["SI-16"], "exploitation_score": 6.0, "impact_score": 6.0, "cwe": "", "cve_id": "", "risk_context": "Memory protection risk"}
    ]
    all_risks["fallback"] = fallback_risks
    
    return all_risks
