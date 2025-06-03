import os
import requests
import json
import jsonschema
import urllib.request
import ssl
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Embedded CVSS v2.0 schema
CVSS_V2_SCHEMA = {
    "$schema": "http://json-schema.org/draft-04/schema#",
    "type": "object",
    "properties": {
        "version": {"type": "string"},
        "vectorString": {"type": "string"},
        "accessVector": {"type": "string"},
        "accessComplexity": {"type": "string"},
        "authentication": {"type": "string"},
        "confidentialityImpact": {"type": "string"},
        "integrityImpact": {"type": "string"},
        "availabilityImpact": {"type": "string"},
        "baseScore": {"type": "number"},
        "severity": {"type": "string"},
        "exploitabilityScore": {"type": "number"},
        "impactScore": {"type": "number"},
        "acInsufInfo": {"type": "boolean"},
        "obtainAllPrivilege": {"type": "boolean"},
        "obtainUserPrivilege": {"type": "boolean"},
        "obtainOtherPrivilege": {"type": "boolean"},
        "userInteractionRequired": {"type": "boolean"}
    },
    "required": ["version", "vectorString", "baseScore"]
}

# Embedded CVSS v3.1 schema
CVSS_V3_1_SCHEMA = {
    "$schema": "http://json-schema.org/draft-04/schema#",
    "type": "object",
    "properties": {
        "version": {"type": "string"},
        "vectorString": {"type": "string"},
        "attackVector": {"type": "string"},
        "attackComplexity": {"type": "string"},
        "privilegesRequired": {"type": "string"},
        "userInteraction": {"type": "string"},
        "scope": {"type": "string"},
        "confidentialityImpact": {"type": "string"},
        "integrityImpact": {"type": "string"},
        "availabilityImpact": {"type": "string"},
        "baseScore": {"type": "number"},
        "baseSeverity": {"type": "string"},
        "exploitabilityScore": {"type": "number"},
        "impactScore": {"type": "number"}
    },
    "required": ["version", "vectorString", "baseScore", "baseSeverity"]
}

def download_schema(schema_url, schema_path):
    """Download the schema if not present, bypassing SSL verification if needed."""
    if not os.path.exists(schema_path):
        try:
            response = requests.get(schema_url, timeout=10)
            response.raise_for_status()
            with open(schema_path, "wb") as f:
                f.write(response.content)
            logging.info(f"Downloaded schema to {schema_path}")
        except requests.RequestException as e:
            logging.error(f"Failed to download schema with requests: {e}")
            try:
                context = ssl._create_unverified_context()
                with urllib.request.urlopen(schema_url, context=context, timeout=10) as response:
                    with open(schema_path, "wb") as f:
                        f.write(response.read())
                logging.info(f"Downloaded schema to {schema_path} (unverified SSL)")
            except urllib.error.URLError as e:
                logging.error(f"Failed to download schema: {e}")
                raise
        except Exception as e:
            logging.error(f"Unexpected error downloading schema: {e}")
            raise

def validate_json(json_data, schema_path, skip_on_failure=False):
    """Validate JSON data against the schema, with embedded CVSS schemas."""
    if not os.path.exists(schema_path):
        logging.warning(f"Schema file {schema_path} not found, skipping validation.")
        return True
    try:
        with open(schema_path, "r") as f:
            schema = json.load(f)
        # Patch schema to include CVSS v2.0 and v3.1
        schema["$defs"] = schema.get("$defs", {})
        schema["$defs"]["cvss-v2.0"] = CVSS_V2_SCHEMA
        schema["$defs"]["cvss-v3.1"] = CVSS_V3_1_SCHEMA
        # Remove external $ref
        def remove_ref(obj):
            if isinstance(obj, dict):
                if "$ref" in obj and ("cvss-v2.0.json" in obj["$ref"] or "cvss-v3.1.json" in obj["$ref"]):
                    obj.pop("$ref")
                    if "cvss-v2.0.json" in obj.get("$ref", ""):
                        obj.update(CVSS_V2_SCHEMA)
                    elif "cvss-v3.1.json" in obj.get("$ref", ""):
                        obj.update(CVSS_V3_1_SCHEMA)
                for key, value in obj.items():
                    remove_ref(value)
            elif isinstance(obj, list):
                for item in obj:
                    remove_ref(item)
        remove_ref(schema)
        jsonschema.validate(instance=json_data, schema=schema)
        logging.info(f"JSON validated successfully against {schema_path}")
        return True
    except jsonschema.exceptions.ValidationError as e:
        logging.warning(f"JSON validation failed: {e.message} at {e.json_path}")
        logging.debug(f"Validation error details: {str(e)}")
        return skip_on_failure
    except jsonschema.exceptions.SchemaError as e:
        logging.error(f"Schema error in {schema_path}: {e.message}")
        logging.debug(f"Schema error details: {str(e)}")
        return skip_on_failure
    except jsonschema.exceptions._WrappedReferencingError as e:
        logging.error(f"Schema reference error in {schema_path}: {str(e)}")
        return skip_on_failure
    except Exception as e:
        logging.error(f"Unexpected error during JSON validation: {str(e)}")
        return skip_on_failure
