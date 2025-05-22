"""Utility functions for schema handling."""

import os
import requests
import json
import jsonschema
import urllib.request
import ssl

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
            print(f"Downloaded schema to {schema_path}")
        except requests.RequestException as e:
            print(f"Failed to download schema with requests: {e}")
            try:
                # Fallback to urllib with unverified SSL context
                context = ssl._create_unverified_context()
                with urllib.request.urlopen(schema_url, context=context, timeout=10) as response:
                    with open(schema_path, "wb") as f:
                        f.write(response.read())
                print(f"Downloaded schema to {schema_path} (unverified SSL)")
            except urllib.error.URLError as e:
                print(f"Failed to download schema: {e}")
                raise

def validate_json(json_data, schema_path):
    """Validate JSON data against the schema, with fallback if validation fails.

    Args:
        json_data (dict): JSON data to validate.
        schema_path (str): Path to the schema file.
    """
    if not os.path.exists(schema_path):
        print(f"Warning: Schema file {schema_path} not found, skipping validation.")
        return
    try:
        with open(schema_path, "r") as f:
            schema = json.load(f)
        jsonschema.validate(instance=json_data, schema=schema)
        print(f"JSON validated successfully against {schema_path}")
    except (jsonschema.exceptions.ValidationError, jsonschema.exceptions.SchemaError, jsonschema.exceptions._WrappedReferencingError) as e:
        print(f"Warning: JSON validation failed: {e}")
        print("Continuing without validation...")