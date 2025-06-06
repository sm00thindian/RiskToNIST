import os
import json
import jsonschema
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def load_schema(schema_path):
    """Load a schema from the given path."""
    try:
        with open(schema_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        logging.error(f"Failed to load schema from {schema_path}: {e}")
        raise

def validate_json(json_data, schema_path, cvss_schemas, skip_on_failure=False):
    """Validate JSON data against the schema, using dynamically loaded CVSS schemas."""
    if not os.path.exists(schema_path):
        logging.warning(f"Schema file {schema_path} not found, skipping validation.")
        return True
    try:
        schema = load_schema(schema_path)
        # Patch schema to include CVSS schemas dynamically
        schema["$defs"] = schema.get("$defs", {})
        for version, cvss_schema in cvss_schemas.items():
            schema["$defs"][f"cvss-v{version}"] = cvss_schema
        # Remove external $ref and replace with local definitions
        def remove_ref(obj):
            if isinstance(obj, dict):
                if "$ref" in obj and any(f"cvss-v{ver}.json" in obj["$ref"] for ver in cvss_schemas.keys()):
                    ref_version = next(ver for ver in cvss_schemas.keys() if f"cvss-v{ver}.json" in obj["$ref"])
                    obj.pop("$ref")
                    if ref_version in cvss_schemas:
                        obj.update(cvss_schemas[ref_version])
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
        return skip_on_failure
    except Exception as e:
        logging.error(f"Unexpected error during JSON validation: {str(e)}")
        return skip_on_failure
