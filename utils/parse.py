import json
import logging
import os
from decimal import Decimal
from .schema import validate_json
import ijson
import glob
import jsonschema

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def convert_decimals(obj):
    """Recursively convert Decimal objects to float."""
    if isinstance(obj, Decimal):
        return float(obj)
    elif isinstance(obj, dict):
        return {k: convert_decimals(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_decimals(item) for item in obj]
    return obj

def load_cvss_schemas():
    """Load CVSS schemas from project root."""
    schema_files = {
        '2.0': 'cvss-v2.0.json',
        '3.0': 'cvss-v3.0.json',
        '3.1': 'cvss-v3.1.json',
        '4.0': 'cvss-v4.0.json'
    }
    schemas = {}
    for version, filename in schema_files.items():
        try:
            with open(filename, 'r') as f:
                schemas[version] = json.load(f)
        except Exception as e:
            logging.warning(f"Failed to load CVSS schema {filename}: {e}")
    return schemas

def validate_cve_metrics(metrics, cvss_schemas):
    """Validate CVE metrics against the appropriate CVSS schema."""
    for metric_key in ['cvssMetricV2', 'cvssMetricV30', 'cvssMetricV31', 'cvssMetricV40']:
        if metric_key in metrics:
            version_map = {
                'cvssMetricV2': '2.0',
                'cvssMetricV30': '3.0',
                'cvssMetricV31': '3.1',
                'cvssMetricV40': '4.0'
            }
            version = version_map[metric_key]
            schema = cvss_schemas.get(version)
            if not schema:
                logging.warning(f"No schema found for CVSS version {version}")
                continue
            for metric in metrics[metric_key]:
                try:
                    jsonschema.validate(instance=metric.get('cvssData', {}), schema=schema)
                except jsonschema.exceptions.ValidationError as e:
                    logging.warning(f"CVSS {version} validation failed: {e.message}")
    return True

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
        cvss_schemas = load_cvss_schemas()
        
        # Check file size and first few bytes
        file_size = os.path.getsize(file_path)
        logging.debug(f"File size: {file_size} bytes")
        with open(file_path, "r", encoding="utf-8") as f:
            first_bytes = f.read(100)
            logging.debug(f"First 100 bytes: {first_bytes[:50]}...")

        # Validate JSON and check for vulnerabilities array
        with open(file_path, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError as e:
                logging.error(f"Invalid JSON in {file_path}: {e}")
                return []
            
            root_keys = list(data.keys())
            logging.debug(f"JSON root keys: {root_keys}")
            if 'vulnerabilities' not in data:
                logging.error(f"No vulnerabilities array found in {file_path}. Root keys: {root_keys}")
                return []
            if not data['vulnerabilities']:
                logging.info(f"Empty vulnerabilities array in {file_path}")
                return []

        # Validate full file schema if provided
        if schema_path:
            logging.debug(f"Validating NVD CVE data against schema: {schema_path}")
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if not validate_json(data, schema_path, skip_on_failure=True):
                    logging.warning(f"Continuing parsing {file_path} despite schema validation failure")

        with open(file_path, "rb") as f:
            risks = []
            skipped_items = 0
            item_count = 0
            logging.info(f"Streaming vulnerabilities.item from {file_path}")

            for item in ijson.items(f, "vulnerabilities.item"):
                item_count += 1
                if item_count % 100 == 0:
                    logging.info(f"Processed {item_count} items in {file_path}")

                item = convert_decimals(item)
                cve_data = item.get("cve", {})
                cve_id = cve_data.get("id", "")
                if not cve_id:
                    skipped_items += 1
                    continue
                
                # Validate metrics against appropriate CVSS schema
                metrics = cve_data.get("metrics", {})
                validate_cve_metrics(metrics, cvss_schemas)
                
                cwe_id = ""
                for problem in cve_data.get("weaknesses", []):
                    for desc in problem.get("description", []):
                        if desc.get("value", "").startswith("CWE-"):
                            cwe_id = desc.get("value", "")
                            break
                    if cwe_id:
                        break
                
                # Prioritize CVSS v3.1, then v4.0, v3.0, v2.0
                cvss_data = None
                for metric_key in ['cvssMetricV31', 'cvssMetricV40', 'cvssMetricV30', 'cvssMetricV2']:
                    if metric_key in metrics and metrics[metric_key]:
                        cvss_data = metrics[metric_key][0].get("cvssData", {})
                        break
                
                if not cvss_data:
                    logging.debug(f"No CVSS data for CVE {cve_id} in {file_path}")
                    base_score = 0.0
                else:
                    base_score = float(cvss_data.get("baseScore", 0.0))
                
                description = next(
                    (desc.get("value", "") for desc in cve_data.get("descriptions", []) if desc.get("lang") == "en"),
                    ""
                )
                risks.append({
                    "mitigating_controls": ["SI-2", "RA-5"],
                    "exploitation_score": base_score,
                    "impact_score": base_score,
                    "cwe": cwe_id,
                    "cve_id": cve_id,
                    "risk_context": description
                })
                if item_count == 1:
                    logging.debug(f"First CVE structure: {json.dumps(item, indent=2)[:1000]}...")
        
        logging.info(f"Processed {item_count} total items in {file_path}")
        if skipped_items > 0:
            logging.info(f"Skipped {skipped_items} items in {file_path} due to missing CVE ID")
        logging.info(f"Parsed {len(risks)} risks from {file_path}")
        if len(risks) == 0:
            logging.warning(f"No risks parsed from {file_path}. Root keys: {root_keys}")
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
            score = float(capability_scores.get(capability_group, 7.0))
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
    
    # Process all NVD files matching nvdcve-*.json
    nvd_files = glob.glob(os.path.join(data_dir, "nvdcve-*.json"))
    schema_path = os.path.join(data_dir, "nvd_cve_schema.json")
    schema_path = schema_path if os.path.exists(schema_path) else None
    for nvd_path in sorted(nvd_files):
        file_name = os.path.basename(nvd_path)
        risks = parse_nvd_cve(nvd_path, schema_path)
        if risks is not None:
            all_risks[f"nvd_{file_name}"] = risks
    
    kev_attack_path = os.path.join(data_dir, "kev_attack_mapping.json")
    if os.path.exists(kev_attack_path):
        all_risks["kev_attack"] = parse_kev_attack_mapping(kev_attack_path, attack_mappings)
    
    return all_risks
