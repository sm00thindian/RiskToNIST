import json
import logging
import os
from datetime import datetime
from .schema import validate_json
import ijson

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def parse_cisa_kev(file_path):
    """Parse CISA KEV CSV file and return a list of risks."""
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
            cwe_id = ""
            risks.append({
                "mitigating_controls": ["SI-2", "RA-5", "SC-7"],
                "exploitation_score": 9.0,
                "impact_score": 9.0,
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
    """Parse NVD CVE JSON file and return a list of risks after schema validation."""
    try:
        logging.debug(f"Attempting to parse NVD CVE file: {file_path}")
        with open(file_path, "rb") as f:
            # Detect structure
            parser = ijson.parse(f)
            has_vulnerabilities = False
            has_cve_items = False
            root_keys = []
            for prefix, event, value in parser:
                if event == "map_key" and not prefix:
                    root_keys.append(value)
                if prefix == "vulnerabilities" and event == "start_array":
                    has_vulnerabilities = True
                elif prefix == "CVE_Items" and event == "start_array":
                    has_cve_items = True
                if has_vulnerabilities or has_cve_items or len(root_keys) > 0:
                    break
        
        # Validate schema
        with open(file_path, "rb") as f:
            if schema_path:
                logging.debug(f"Validating NVD CVE data against schema: {schema_path}")
                data = json.load(f)
                if not validate_json(data, schema_path, skip_on_failure=True):
                    logging.warning(f"Continuing parsing {file_path} despite schema validation failure")
                f.seek(0)
            else:
                data = None
            
            risks = []
            skipped_items = 0
            item_count = 0
            key = "vulnerabilities.item" if has_vulnerabilities else "CVE_Items.item"
            logging.info(f"Streaming {key} from {file_path}")
            
            for item in ijson.items(f, key):
                item_count += 1
                if item_count % 100 == 0:
                    logging.info(f"Processed {item_count} items in {file_path}")
                
                cve_data = item.get("cve") if has_cve_items else item
                cve_id = cve_data.get("id", "")
                if not cve_id:
                    skipped_items += 1
                    continue
                cwe_id = ""
                for problem in cve_data.get("weaknesses", []):
                    for desc in problem.get("description", []):
                        if desc.get("value", "").startswith("CWE-"):
                            cwe_id = desc.get("value", "")
                            break
                    if cwe_id:
                        break
                cvss_v3 = cve_data.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {})
                base_score = float(cvss_v3.get("baseScore", 0.0))  # Ensure float
                description = cve_data.get("descriptions", [{}])[0].get("value", "")
                risks.append({
                    "mitigating_controls": ["SI-2", "RA-5"],
                    "exploitation_score": base_score,
                    "impact_score": base_score,
                    "cwe": cwe_id,
                    "cve_id": cve_id,
                    "risk_context": description
                })
        
        logging.info(f"Processed {item_count} total items in {file_path}")
        if skipped_items > 0:
            logging.info(f"Skipped {skipped_items} items in {file_path} due to missing CVE ID")
        logging.info(f"Parsed {len(risks)} risks from {file_path}")
        if len(risks) == 0 and not has_vulnerabilities and not has_cve_items:
            logging.warning(f"No valid vulnerabilities or CVE_Items found in {file_path}. Root keys: {root_keys}")
        return risks
    except Exception as e:
        logging.error(f"Failed to parse NVD CVE file {file_path}: {e}")
        return []

def parse_kev_attack_mapping(json_path, attack_mappings):
    """Parse KEV to ATT&CK mapping JSON file and return a list of risks."""
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
                controls = ["SI-2"]
            score = float(capability_scores.get(capability_group, 7.0))  # Ensure float
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
    """Parse all datasets and return a dictionary of risks by source."""
    all_risks = {}
    
    cisa_kev_path = os.path.join(data_dir, "cisa_kev.csv")
    if os.path.exists(cisa_kev_path):
        all_risks["cisa_kev"] = parse_cisa_kev(cisa_kev_path)
    
    for file_name in os.listdir(data_dir):
        if file_name.startswith("nvdcve-1.1-") and file_name.endswith(".json"):
            nvd_path = os.path.join(data_dir, file_name)
            schema_path = os.path.join(data_dir, "nvd_cve_schema.json")
            all_risks[f"nvd_{file_name}"] = parse_nvd_cve(nvd_path, schema_path if os.path.exists(schema_path) else None)
    
    kev_attack_path = os.path.join(data_dir, "kev_attack_mapping.json")
    if os.path.exists(kev_attack_path):
        all_risks["kev_attack"] = parse_kev_attack_mapping(kev_attack_path, attack_mappings)
    
    return all_risks
