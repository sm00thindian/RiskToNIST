import os
import requests
import json
import jsonschema
import urllib.request
import ssl
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

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
    """Validate JSON data against the schema, using local CVSS schemas."""
    if not os.path.exists(schema_path):
        logging.warning(f"Schema file {schema_path} not found, skipping validation.")
        return True
    try:
        with open(schema_path, "r") as f:
            schema = json.load(f)
        # Load local CVSS schemas
        cvss_schemas = {}
        for version in ['2.0', '3.0', '3.1', '4.0']:
            cvss_schema_path = f"cvss-v{version}.json"
            if os.path.exists(cvss_schema_path):
                with open(cvss_schema_path, "r") as f:
                    cvss_schemas[version] = json.load(f)
            else:
                logging.warning(f"CVSS schema {cvss_schema_path} not found in project root.")
        
        # Patch schema to include CVSS schemas
        schema["$defs"] = schema.get("$defs", {})
        for version, cvss_schema in cvss_schemas.items():
            schema["$defs"][f"cvss-v{version}"] = cvss_schema
        
        # Remove external $ref to CVSS schemas
        def remove_ref(obj):
            if isinstance(obj, dict):
                if "$ref" in obj and any(f"cvss-v{ver}.json" in obj["$ref"] for ver in ['2.0', '3.0', '3.1', '4.0']):
                    ref_version = next(ver for ver in ['2.0', '3.0', '3.1', '4.0'] if f"cvss-v{ver}.json" in obj["$ref"])
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
