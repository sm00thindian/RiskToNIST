"""Utility functions for schema handling."""

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
    """Download the schema if not present, bypassing SSL verification if needed.

    Args:
        schema_url (str): URL of the schema.
        schema_path (str): Path to save the schema.
    """
    if not os.path.exists(schema_path):
        try:
            # Try with requests first (uses certifi)
            response = requests.get(schema_url, timeout=10)
            response.raise_for_status()
            with open(schema_path, "wb") as f:
                f.write(response.content)
            logging.info(f"Downloaded schema to {schema_path}")
        except requests.RequestException as e:
            logging.error(f"Failed to download schema with requests: {e}")
            try:
                # Fallback to urllib with unverified SSL context
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
    """Validate JSON data against the schema, with option to skip on failure.

    Args:
        json_data (dict): JSON data to validate.
        schema_path (str): Path to the schema file.
        skip_on_failure (bool): If True, log warning and continue on validation failure.
    """
    if not os.path.exists(schema_path):
        logging.warning(f"Schema file {schema_path} not found, skipping validation.")
        return True
    try:
        with open(schema_path, "r") as f:
            schema = json.load(f)
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
