import json
import logging
import os
from .schema import load_schema, validate_json
import ijson

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def load_cvss_schemas():
    """Load CVSS schemas from the project root."""
    schema_files = {
        '2.0': 'cvss-v2.0.json',
        '3.0': 'cvss-v3.0.json',
        '3.1': 'cvss-v3.1.json',
        '4.0': 'cvss-v4.0.json'
    }
    schemas = {}
    for version, filename in schema_files.items():
        try:
            if os.path.exists(filename):
                schemas[version] = load_schema(filename)
            else:
                logging.warning(f"CVSS schema {filename} not found in project root.")
        except Exception as e:
            logging.warning(f"Failed to load CVSS schema {filename}: {e}")
    return schemas

def parse_nvd_cve(file_path, schema_path="data/nvd_cve_schema.json"):
    """Parse NVD CVE JSON file and return a list of risks after schema validation."""
    try:
        logging.debug(f"Attempting to parse NVD CVE file: {file_path}")
        cvss_schemas = load_cvss_schemas()
        
        # Validate JSON and check for vulnerabilities array
        with open(file_path, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError as e:
                logging.error(f"Invalid JSON in {file_path}: {e}")
                return []
            
            if 'vulnerabilities' not in data:
                logging.error(f"No vulnerabilities array found in {file_path}.")
                return []
            if not data['vulnerabilities']:
                logging.info(f"Empty vulnerabilities array in {file_path}")
                return []

        # Validate full file schema if provided
        if schema_path:
            logging.debug(f"Validating NVD CVE data against schema: {schema_path}")
            if not validate_json(data, schema_path, cvss_schemas, skip_on_failure=True):
                logging.warning(f"Continuing parsing {file_path} despite schema validation failure")

        with open(file_path, "rb") as f:
            risks = []
            for item in ijson.items(f, "vulnerabilities.item"):
                cve_data = item.get("cve", {})
                cve_id = cve_data.get("id", "")
                if not cve_id:
                    continue
                
                metrics = cve_data.get("metrics", {})
                # Validate metrics against appropriate CVSS schema
                for metric_key in ['cvssMetricV2', 'cvssMetricV30', 'cvssMetricV31', 'cvssMetricV40']:
                    if metric_key in metrics:
                        version = metric_key.replace('cvssMetricV', '').replace('0', '.0')
                        if version in cvss_schemas:
                            for metric in metrics[metric_key]:
                                try:
                                    jsonschema.validate(instance=metric.get('cvssData', {}), schema=cvss_schemas[version])
                                except jsonschema.exceptions.ValidationError as e:
                                    logging.warning(f"CVSS {version} validation failed for CVE {cve_id}: {e.message}")
                
                # Extract risk data
                risks.append({
                    "mitigating_controls": ["SI-2", "RA-5"],
                    "exploitation_score": 0.0,  # Placeholder
                    "impact_score": 0.0,  # Placeholder
                    "cwe": "",  # Placeholder
                    "cve_id": cve_id,
                    "risk_context": ""  # Placeholder
                })
        
        logging.info(f"Parsed {len(risks)} risks from {file_path}")
        return risks
    except Exception as e:
        logging.error(f"Failed to parse NVD CVE file {file_path}: {e}")
        return []
