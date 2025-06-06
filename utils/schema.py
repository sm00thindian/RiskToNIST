import os
import requests
import json
import jsonschema
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def download_schema(schema_url, schema_path):
    """Download the schema from the given URL and save it to the specified path."""
    if os.path.exists(schema_path):
        logging.debug(f"Schema file {schema_path} already exists, skipping download.")
        return
    try:
        response = requests.get(schema_url, timeout=10)
        response.raise_for_status()
        os.makedirs(os.path.dirname(schema_path), exist_ok=True)
        with open(schema_path, "wb") as f:
            f.write(response.content)
        logging.info(f"Downloaded schema from {schema_url} to {schema_path}")
    except requests.RequestException as e:
        logging.error(f"Failed to download schema from {schema_url}: {e}")
        raise

def load_schema(schema_path):
    """Load a schema from the given path."""
    try:
        with open(schema_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        logging.error(f"Failed to load schema from {schema_path}: {e}")
        raise

def validate_json(json_data, schema_path, cvss_schemas=None, skip_on_failure=False):
    """Validate JSON data against the schema, embedding CVSS schemas."""
    if not os.path.exists(schema_path):
        logging.warning(f"Schema file {schema_path} not found, skipping validation.")
        return True
    try:
        schema = load_schema(schema_path)
        if cvss_schemas:
            # Embed CVSS schemas into definitions
            schema["definitions"] = schema.get("definitions", {})
            for version, cvss_schema in cvss_schemas.items():
                v = version.replace('.', '')
                # Embed CVSS schema
                schema["definitions"][f"cvss-v{v}"] = cvss_schema
                # Copy all CVSS internal definitions to top-level
                for def_key, def_value in cvss_schema.get("definitions", {}).items():
                    schema["definitions"][def_key] = def_value
            # Update references
            def update_refs(obj):
                if isinstance(obj, dict):
                    if "$ref" in obj:
                        ref = obj["$ref"]
                        for version in cvss_schemas.keys():
                            v = version.replace('.', '')
                            if f"cvss-v{version}" in ref:
                                obj["$ref"] = f"#/definitions/cvss-v{v}"
                            elif any(def_key in ref for def_key in cvss_schemas.get('2.0', {}).get("definitions", {})):
                                # Direct reference to CVSS v2.0 definitions (e.g., accessVectorType)
                                def_key = ref.split('/')[-1]
                                obj["$ref"] = f"#/definitions/{def_key}"
                    for key, value in obj.items():
                        update_refs(value)
                elif isinstance(obj, list):
                    for item in obj:
                        update_refs(item)
            update_refs(schema)
        jsonschema.validate(instance=json_data, schema=schema)
        logging.info(f"JSON validated successfully against {schema_path}")
        return True
    except jsonschema.exceptions.ValidationError as e:
        logging.warning(f"JSON validation failed: {e.message} at {e.json_path}")
        return skip_on_failure
    except Exception as e:
        logging.error(f"Unexpected error during JSON validation: {str(e)}")
        return skip_on_failure
