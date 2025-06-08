import json
import logging
import os
import glob
from datetime import datetime
from decimal import Decimal
import ijson
import jsonschema
import pandas as pd
from .schema import load_schema, validate_json

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def load_cvss_schemas():
    """Load CVSS schemas from the project root.

    Returns:
        dict: Dictionary of CVSS schemas by version.
    """
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

def to_float(value):
    """Convert value to float, handling Decimal types.

    Args:
        value: Value to convert.

    Returns:
        float: Converted value, or 0.0 if None.
    """
    if isinstance(value, Decimal):
        return float(value)
    return float(value) if value is not None else 0.0

def normalize_cvss_data(data):
    """Recursively normalize CVSS data, handling None and NOT_DEFINED values.

    Args:
        data: Data to normalize.

    Returns:
        Normalized data structure, or None if invalid.
    """
    if isinstance(data, dict):
        normalized = {}
        required_fields = ['version', 'vectorString', 'baseScore', 'baseSeverity']
        optional_fields = [
            'vulnerabilityResponseEffort', 'exploitMaturity', 'confidentialityRequirement',
            'integrityRequirement', 'availabilityRequirement', 'vulnConfidentialityImpact',
            'vulnIntegrityImpact', 'vulnAvailabilityImpact', 'subConfidentialityImpact',
            'subIntegrityImpact', 'subAvailabilityImpact'
        ]
        for k, v in data.items():
            if k in required_fields and v is None:
                logging.debug(f"Skipping CVSS data due to None value in required field: {k}")
                return None
            elif k in optional_fields and v is None:
                normalized[k] = "NOT_DEFINED"  # Set default for optional fields
            elif v == "NOT_DEFINED":
                normalized[k] = None
            else:
                normalized[k] = normalize_cvss_data(v)
        return normalized
    elif isinstance(data, list):
        return [normalize_cvss_data(item) for item in data if normalize_cvss_data(item) is not None]
    elif isinstance(data, (Decimal, int, float)):
        return float(data)
    elif data is None:
        return None
    return data

def parse_nvd_cve(file_path, schema_path="cve_api_json_2.0.schema"):
    """Parse NVD CVE JSON file and return a list of risks with API and schema validation.

    Args:
        file_path (str): Path to NVD CVE JSON file.
        schema_path (str): Path to JSON schema for validation.

    Returns:
        list: List of parsed risk dictionaries.
    """
    try:
        logging.debug(f"Parsing NVD CVE file: {file_path}")
        cvss_schemas = load_cvss_schemas()

        with open(file_path, "r", encoding="utf-8") as f:
            try:
                data = json.load(f, parse_float=float)
            except json.JSONDecodeError as e:
                logging.error(f"Invalid JSON in {file_path}: {e}")
                return []

            if 'vulnerabilities' not in data:
                logging.error(f"No vulnerabilities array found in {file_path}.")
                return []
            if not data['vulnerabilities']:
                logging.info(f"Empty vulnerabilities array in {file_path}")
                return []

        if schema_path:
            logging.debug(f"Validating NVD CVE data against API schema: {schema_path}")
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
                impact_score = 0.0
                exploit_maturity = "UNREPORTED"

                for metric_key, version in [
                    ('cvssMetricV2', '2.0'),
                    ('cvssMetricV30', '3.0'),
                    ('cvssMetricV31', '3.1'),
                    ('cvssMetricV40', '4.0')
                ]:
                    if metric_key in metrics and metrics[metric_key]:
                        schema = cvss_schemas.get(version)
                        for metric in metrics[metric_key]:
                            cvss_data = normalize_cvss_data(metric.get('cvssData', {}))
                            if cvss_data is None:
                                logging.warning(f"Skipping CVSS {version} data for CVE {cve_id}: Invalid or missing required fields")
                                continue
                            try:
                                if schema:
                                    jsonschema.validate(instance=cvss_data, schema=schema)
                                base_score = to_float(cvss_data.get('baseScore', 0.0))
                                if base_score > exploitation_score:
                                    exploitation_score = base_score
                                if version == '2.0':
                                    impact_subscore = to_float(cvss_data.get('impactSubScore', 0.0))
                                    if impact_subscore > impact_score:
                                        impact_score = impact_subscore
                                elif version in ['3.0', '3.1']:
                                    impact_subscore = to_float(cvss_data.get('impactScore', 0.0))
                                    exploitability_score = to_float(cvss_data.get('exploitabilityScore', 0.0))
                                    if impact_subscore > impact_score:
                                        impact_score = impact_subscore
                                    if exploitability_score > exploitation_score:
                                        exploitation_score = exploitability_score
                                elif version == '4.0':
                                    cia_weights = {'HIGH': 1.0, 'LOW': 0.5, 'NONE': 0.0}
                                    c_score = cia_weights.get(cvss_data.get('vulnConfidentialityImpact', 'NONE'), 0.0)
                                    i_score = cia_weights.get(cvss_data.get('vulnIntegrityImpact', 'NONE'), 0.0)
                                    a_score = cia_weights.get(cvss_data.get('vulnAvailabilityImpact', 'NONE'), 0.0)
                                    calculated_impact = (to_float(c_score) + to_float(i_score) + to_float(a_score)) / 3.0 * 10.0
                                    if calculated_impact > impact_score:
                                        impact_score = calculated_impact
                                        exploit_maturity = cvss_data.get('exploitMaturity', 'UNREPORTED') or "UNREPORTED"
                            except jsonschema.exceptions.ValidationError as e:
                                logging.warning(f"CVSS {version} validation failed for CVE {cve_id}: {e.message} at {e.path}")
                                continue

                weaknesses = cve_data.get("weaknesses", [])
                cwe = weaknesses[0]["description"][0]["value"] if weaknesses and weaknesses[0]["description"] else ""
                description = cve_data.get("descriptions", [{}])[0].get("value", "")
                pub_date = cve_data.get("published", "")
                try:
                    if pub_date:
                        pub_date = datetime.strptime(pub_date, "%Y-%m-%dT%H:%M:%S.%f")
                    else:
                        pub_date = None
                except ValueError:
                    try:
                        pub_date = datetime.strptime(pub_date, "%Y-%m-%dT%H:%M:%S")
                    except ValueError as e:
                        logging.error(f"Failed to parse date '{pub_date}' in {file_path}: {e}")
                        pub_date = None

                risks.append({
                    "mitigating_controls": ["SI-2", "RA-5"],
                    "exploitation_score": float(exploitation_score),
                    "impact_score": float(impact_score),
                    "exploit_maturity": exploit_maturity,
                    "cve_id": cve_id,
                    "cwe": cwe,
                    "risk_context": description,
                    "published_date": pub_date
                })

        logging.info(f"Parsed {len(risks)} risks from {file_path}")
        return risks
    except Exception as e:
        logging.error(f"Failed to parse NVD CVE file {file_path}: {e}")
        return []

def parse_cisa_kev(file_path):
    """Parse CISA KEV CSV file and return a list of risks.

    Args:
        file_path (str): Path to CISA KEV CSV file.

    Returns:
        list: List of parsed risk dictionaries.
    """
    try:
        logging.debug(f"Attempting to parse CISA KEV file: {file_path}")
        df = pd.read_csv(file_path)
        logging.debug(f"Successfully loaded CISA KEV with {len(df)} entries")
        risks = []
        for _, row in df.iterrows():
            cve_id = row.get("cveID", "")
            if not cve_id:
                continue
            cwe_id = row.get("cweID", "") if "cweID" in row else ""
            pub_date = row.get("dateAdded", "")
            pub_date = datetime.strptime(pub_date, "%Y-%m-%d") if pub_date else None
            risks.append({
                "mitigating_controls": ["SI-2", "RA-5", "SC-7"],
                "exploitation_score": 9.0,
                "impact_score": 9.0,
                "exploit_maturity": "ATTACKED",
                "cve_id": cve_id,
                "cwe": cwe_id,
                "risk_context": f"CISA KEV: {row.get('vulnerabilityName', '')}",
                "published_date": pub_date
            })
        logging.info(f"Parsed {len(risks)} risks from {file_path}")
        return risks
    except Exception as e:
        logging.error(f"Failed to parse CISA KEV file {file_path}: {e}")
        return []

def parse_kev_attack_mapping(json_path, attack_mappings):
    """Parse KEV to ATT&CK mapping JSON file and return a list of risks.

    Args:
        json_path (str): Path to KEV ATT&CK mapping JSON file.
        attack_mappings (dict): ATT&CK to NIST control mappings.

    Returns:
        list: List of parsed risk dictionaries.
    """
    try:
        logging.debug(f"Attempting to parse KEV ATT&CK mapping file: {json_path}")
        with open(json_path, "r") as f:
            data = json.load(f, parse_float=float)
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
            cwe_id = item.get("cwe_id", "") if item.get("cwe_id") else ""
            pub_date = item.get("published_date", "")
            pub_date = datetime.strptime(pub_date, "%Y-%m-%d") if pub_date else None
            risks.append({
                "mitigating_controls": controls,
                "exploitation_score": score,
                "impact_score": score,
                "exploit_maturity": "ATTACKED",
                "cve_id": cve_id,
                "cwe": cwe_id,
                "risk_context": item.get("comments", ""),
                "published_date": pub_date
            })
        logging.info(f"Parsed {len(risks)} risks from {json_path}")
        return risks
    except Exception as e:
        logging.error(f"Failed to parse KEV ATT&CK mapping file {json_path}: {e}")
        return []

def parse_all_datasets(data_dir, attack_mappings, config):
    """Parse all enabled datasets and return a dictionary of risks by source.

    Args:
        data_dir (str): Directory containing dataset files.
        attack_mappings (dict): ATT&CK to NIST control mappings.
        config (dict): Configuration dictionary from config.json.

    Returns:
        dict: Dictionary of risks by source.
    """
    all_risks = {}

    for source in config.get("sources", []):
        name = source.get("name", "")
        enabled = source.get("enabled", True)
        output_file = source.get("output", "")

        if not enabled:
            logging.info(f"Skipping disabled source: {name}")
            continue

        if name == "NVD CVE":
            nvd_files = glob.glob(os.path.join(data_dir, "nvdcve-*.json"))
            for file_path in sorted(nvd_files):
                if os.path.exists(file_path):
                    source_key = f"nvd_{os.path.basename(file_path)}"
                    all_risks[source_key] = parse_nvd_cve(file_path)
                else:
                    logging.debug(f"NVD CVE file not found at {file_path}; skipping.")
        elif name == "CISA KEV" and output_file:
            file_path = os.path.join(data_dir, output_file)
            if os.path.exists(file_path):
                all_risks["cisa_kev"] = parse_cisa_kev(file_path)
        elif name == "KEV ATTACK Mapping" and output_file:
            file_path = os.path.join(data_dir, output_file)
            if os.path.exists(file_path):
                all_risks["kev_attack"] = parse_kev_attack_mapping(file_path, attack_mappings)

    logging.info(f"Parsed risks from {len(all_risks)} sources")
    return all_risks
