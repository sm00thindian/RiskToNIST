import pandas as pd
import json
import os
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

def parse_csv(csv_path):
    """Parse a single CSV to extract risks, mitigating controls, and scores.

    Args:
        csv_path (str): Path to the CSV file.

    Returns:
        list: List of dictionaries with risk data.
    """
    try:
        df = pd.read_csv(csv_path)
        risks = []
        source_name = os.path.basename(csv_path).replace(".csv", "")
        for _, row in df.iterrows():
            if source_name == "cisa_kev":
                cve_id = row.get("cveID", "")
                cwe = row.get("cwes", "")
                if not cve_id:
                    logging.warning(f"Skipping row in {csv_path} with missing cveID")
                    continue
                controls = ["SI-2"]  # Flaw Remediation
                if isinstance(cwe, str):
                    if "CWE-22" in cwe:
                        controls.extend(["SC-7"])  # Path Traversal
                    elif "CWE-79" in cwe:
                        controls.extend(["AT-2"])  # XSS
                    elif "CWE-94" in cwe or "CWE-288" in cwe:
                        controls.extend(["AC-2"])  # Code Injection, Auth Bypass
                    elif "CWE-502" in cwe or "CWE-78" in cwe:
                        controls.extend(["SI-10"])  # Deserialization, Command Injection
                    elif "CWE-416" in cwe:
                        controls.extend(["SI-16"])  # Use-After-Free
                    elif "CWE-287" in cwe:
                        controls.extend(["IA-2"])  # Authentication Issues
                    elif "CWE-20" in cwe:
                        controls.extend(["SI-7"])  # Improper Input Validation
                    elif "CWE-400" in cwe or "CWE-770" in cwe:
                        controls.extend(["SC-5"])  # Resource Exhaustion
                    elif "CWE-269" in cwe:
                        controls.extend(["SI-7"])  # Privilege Management
                risks.append({
                    "mitigating_controls": [normalize_control_id(c) for c in controls],
                    "exploitation_score": 10.0,
                    "impact_score": 10.0,
                    "cwe": cwe if isinstance(cwe, str) else "",
                    "cve_id": cve_id
                })
            else:
                controls = row.get("Mitigating Controls", "").split(",")
                controls = [normalize_control_id(ctrl.strip()) for ctrl in controls if ctrl.strip()]
                exploitation_score = float(row.get("Exploitation Score", 0.0))
                impact_score = float(row.get("Impact Score", 0.0))
                risks.append({
                    "mitigating_controls": controls,
                    "exploitation_score": exploitation_score,
                    "impact_score": impact_score,
                    "cwe": ""
                })
        logging.info(f"Parsed {len(risks)} risks from {csv_path} with controls {[r['mitigating_controls'] for r in risks[:5]]}")
        return risks
    except Exception as e:
        logging.error(f"Error parsing {csv_path}: {e}")
        return []

def parse_nvd(data_dir):
    """Parse NVD JSON files to extract CVE IDs and CVSS scores.

    Args:
        data_dir (str): Directory containing NVD JSON files.

    Returns:
        list: List of dictionaries with CVE data.
    """
    paths = [
        os.path.join(data_dir, "nvdcve-1.1-2025.json"),
        os.path.join(data_dir, "nvdcve-1.1-recent.json"),
        os.path.join(data_dir, "nvdcve-1.1-modified.json")
    ]
    cve_dict = {}
    for path in paths:
        if not os.path.exists(path):
            logging.warning(f"{path} not found, skipping.")
            continue
        try:
            with open(path, "r") as f:
                data = json.load(f)
            cve_items = data.get("CVE_Items", [])
            logging.info(f"Found {len(cve_items)} items in {path}")
            for item in cve_items:
                cve = item.get("cve", {})
                cve_id = cve.get("id")
                if cve_id:
                    cve_dict[cve_id] = item
                else:
                    logging.warning(f"Skipping item in {path} with missing cve.id")
        except json.JSONDecodeError as e:
            logging.error(f"Failed to parse {path}: {e}")
            continue
    
    risks = []
    for item in cve_dict.values():
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            logging.warning("Skipping item with missing cve.id")
            continue
        score = 0.0
        metrics = cve.get("metrics", {})
        cvss_v31 = metrics.get("cvssMetricV31", [])
        controls = ["RA-5"]  # Vulnerability Scanning
        weaknesses = cve.get("weaknesses", [{}])[0].get("description", [{}])
        cwe = weaknesses[0].get("value", "") if weaknesses else ""
        if cwe == "CWE-416":
            controls.extend(["SI-2", "SI-16"])  # Use-After-Free
        elif cwe == "CWE-22":
            controls.extend(["SC-7"])  # Path Traversal
        elif cwe == "CWE-79":
            controls.extend(["AT-2"])  # XSS
        elif cwe == "CWE-94" or cwe == "CWE-288":
            controls.extend(["AC-2"])  # Code Injection, Auth Bypass
        elif cwe == "CWE-502" or cwe == "CWE-78":
            controls.extend(["SI-10"])  # Deserialization, Command Injection
        elif cwe == "CWE-287":
            controls.extend(["IA-2"])  # Authentication Issues
        elif cwe == "CWE-20":
            controls.extend(["SI-7"])  # Improper Input Validation
        elif cwe == "CWE-400" or cwe == "CWE-770":
            controls.extend(["SC-5"])  # Resource Exhaustion
        elif cwe == "CWE-269":
            controls.extend(["SI-7"])  # Privilege Management
        if cvss_v31 and len(cvss_v31) > 0:
            cvss_data = cvss_v31[0].get("cvssData", {})
            score = cvss_data.get("baseScore", 0.0)
            logging.debug(f"CVE {cve_id}: CVSS score {score}, controls {controls}, cwe {cwe}")
        else:
            logging.debug(f"CVE {cve_id}: No CVSS v3.1 score, defaulting to 0.0")
        risks.append({
            "mitigating_controls": [normalize_control_id(c) for c in controls],
            "exploitation_score": score,
            "impact_score": score,
            "cwe": cwe,
            "cve_id": cve_id
        })
    logging.info(f"Parsed {len(risks)} CVEs from NVD JSON files")
    return risks

def parse_kev_attack_mapping(json_path, attack_mappings):
    """Parse KEV-to-ATT&CK mapping JSON and cross-reference with ATT&CK-to-NIST.

    Args:
        json_path (str): Path to the KEV ATT&CK mapping JSON file.
        attack_mappings (dict): ATT&CK-to-NIST control mappings.

    Returns:
        list: List of risk dictionaries with controls and scores.
    """
    try:
        with open(json_path, "r") as f:
            data = json.load(f)
        risks = []
        if not isinstance(data.get("mapping_objects"), list):
            logging.error(f"Invalid structure in {json_path}: 'mapping_objects' missing or not a list")
            return []
        
        for item in data["mapping_objects"]:
            if not isinstance(item, dict):
                logging.warning(f"Skipping invalid item in {json_path}: {item}")
                continue
            cve_id = item.get("cve_id")
            technique_id = item.get("attack_object_id")
            if not cve_id or not technique_id:
                logging.warning(f"Skipping item missing cve_id or attack_object_id: {item}")
                continue
            controls = []
            if technique_id in attack_mappings:
                controls = [normalize_control_id(c) for c in attack_mappings[technique_id]]
                logging.debug(f"Mapped {technique_id} to controls: {controls}")
            else:
                logging.debug(f"No NIST controls mapped for technique {technique_id}")
                controls = ["SI-2"]  # Default for KEV vulnerabilities
            risks.append({
                "mitigating_controls": controls,
                "exploitation_score": 10.0,  # KEV vulnerabilities are high priority
                "impact_score": 10.0,
                "cwe": "",
                "cve_id": cve_id
            })
        logging.info(f"Parsed {len(risks)} risks from {json_path} with controls {[r['mitigating_controls'] for r in risks[:5]]}")
        return risks
    except json.JSONDecodeError as e:
        logging.error(f"Error parsing {json_path}: {e}")
        return []
    except Exception as e:
        logging.error(f"Unexpected error parsing {json_path}: {e}")
        return []

def parse_all_datasets(data_dir="data", attack_mappings=None):
    """Parse all datasets (CSV, NVD JSON, KEV ATT&CK JSON) in the data directory.

    Args:
        data_dir (str): Directory containing data files.
        attack_mappings (dict): ATT&CK-to-NIST control mappings for KEV cross-referencing.

    Returns:
        dict: Dictionary mapping source names to lists of risks.
    """
    all_risks = {}
    csv_count = 0
    for filename in os.listdir(data_dir):
        if filename.endswith(".csv"):
            source_name = filename.replace(".csv", "")
            csv_path = os.path.join(data_dir, filename)
            risks = parse_csv(csv_path)
            if risks:
                all_risks[source_name] = risks
                csv_count += 1
        elif filename == "kev_attack_mapping.json":
            risks = parse_kev_attack_mapping(os.path.join(data_dir, filename), attack_mappings or {})
            if risks:
                all_risks["kev_attack"] = risks
    
    # Parse NVD data if present
    if any(os.path.exists(os.path.join(data_dir, f)) for f in ["nvdcve-1.1-2025.json", "nvdcve-1.1-recent.json", "nvdcve-1.1-modified.json"]):
        nvd_risks = parse_nvd(data_dir)
        if nvd_risks:
            all_risks["nvd_cve"] = nvd_risks
    
    # Always include fallback data
    logging.info("Adding fallback risks for additional control coverage")
    all_risks.setdefault("fallback", []).extend([
        {"mitigating_controls": [normalize_control_id("SI-2")], "exploitation_score": 8.0, "impact_score": 8.0, "cwe": ""},  # Vulnerability remediation
        {"mitigating_controls": [normalize_control_id("IA-5")], "exploitation_score": 7.0, "impact_score": 7.0, "cwe": ""},  # Credential abuse
        {"mitigating_controls": [normalize_control_id("AT-2")], "exploitation_score": 6.0, "impact_score": 6.0, "cwe": ""},  # Phishing training
        {"mitigating_controls": [normalize_control_id("SC-8")], "exploitation_score": 6.0, "impact_score": 6.0, "cwe": ""},  # Secure communications
        {"mitigating_controls": [normalize_control_id("CM-6")], "exploitation_score": 6.0, "impact_score": 6.0, "cwe": ""},  # Configuration settings
        {"mitigating_controls": [normalize_control_id("SI-7")], "exploitation_score": 6.0, "impact_score": 6.0, "cwe": ""},  # Software Integrity
        {"mitigating_controls": [normalize_control_id("SC-5")], "exploitation_score": 6.0, "impact_score": 6.0, "cwe": ""},  # Denial of Service Protection
        {"mitigating_controls": [normalize_control_id("IA-2")], "exploitation_score": 6.0, "impact_score": 6.0, "cwe": ""},  # Authentication
        {"mitigating_controls": [normalize_control_id("AC-3")], "exploitation_score": 6.0, "impact_score": 6.0, "cwe": ""},  # Access Enforcement
        {"mitigating_controls": [normalize_control_id("AC-4")], "exploitation_score": 6.0, "impact_score": 6.0, "cwe": ""},  # Information Flow Enforcement
        {"mitigating_controls": [normalize_control_id("AC-6")], "exploitation_score": 6.0, "impact_score": 6.0, "cwe": ""}   # Least Privilege
    ])
    logging.info("Added fallback risks for SI-2, IA-5, AT-2, SC-8, CM-6, SI-7, SC-5, IA-2, AC-3, AC-4, AC-6")
    
    logging.info(f"Parsed risks from {csv_count} CSVs, NVD, and KEV ATT&CK