import json
import logging
import os
from .schema import load_schema, validate_json
import ijson
import jsonschema

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

def parse_nvd_cve(file_path, schema_path="cve_api_json_2.0.schema"):
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
                exploitation_score = 0.0
                if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                    exploitation_score = metrics['cvssMetricV31'][0]['cvssData'].get('baseScore', 0.0)
                
                weaknesses = cve_data.get("weaknesses", [])
                cwe = weaknesses[0]["description"][0]["value"] if weaknesses and weaknesses[0]["description"] else ""
                
                description = cve_data.get("descriptions", [{}])[0].get("value", "")
                
                risks.append({
                    "mitigating_controls": ["SI-2", "RA-5"],
                    "exploitation_score": float(exploitation_score),
                    "impact_score": 0.0,  # Placeholder for impact logic
                    "cve_id": cve_id,
                    "cwe": cwe,
                    "risk_context": description
                })
        
        logging.info(f"Parsed {len(risks)} risks from {file_path}")
        return risks
    except Exception as e:
        logging.error(f"Failed to parse NVD CVE file {file_path}: {e}")
        return []

def parse_all_datasets(data_dir, attack_mappings, config):
    """Parse all enabled datasets and return a dictionary of risks by source."""
    all_risks = {}
    
    # Load config if not provided
    if config is None:
        try:
            with open('config.json', 'r') as f:
                config = json.load(f)
        except Exception as e:
            logging.error(f"Failed to load config: {e}")
            return all_risks
    
    for source in config.get("sources", []):
        name = source.get("name", "")
        enabled = source.get("enabled", True)
        output_file = source.get("output", "")
        
        if not enabled:
            logging.info(f"Skipping disabled source: {name}")
            continue
        
        if name == "NVD CVE":
            if not output_file:
                logging.debug(f"No output file specified for NVD CVE; skipping parsing.")
                continue
            file_path = os.path.join(data_dir, output_file)
            if os.path.exists(file_path):
                all_risks["nvd_cve"] = parse_nvd_cve(file_path)
            else:
                logging.debug(f"NVD CVE file not found at {file_path}; skipping as source is disabled or not downloaded.")
        # Add parsing for other sources as needed
        # Example:
        # elif name == "CISA KEV":
        #     file_path = os.path.join(data_dir, output_file)
        #     if os.path.exists(file_path):
        #         all_risks["cisa_kev"] = parse_cisa_kev(file_path)
    
    logging.info(f"Parsed risks from {len(all_risks)} sources")
    return all_risks
