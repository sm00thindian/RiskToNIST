"""Utility functions for schema handling."""

import os
import requests
import json
import jsonschema

def download_schema(schema_url, schema_path):
    """Download the schema if not present.

    Args:
        schema_url (str): URL of the schema.
        schema_path (str): Path to save the schema.
    """
    if not os.path.exists(schema_path):
        response = requests.get(schema_url, timeout=10)
        with open(schema_path, "wb") as f:
            f.write(response.content)
        print(f"Downloaded schema to {schema_path}")

def validate_json(json_data, schema_path):
    """Validate JSON data against the schema.

    Args:
        json_data (dict): JSON data to validate.
        schema_path (str): Path to the schema file.
    """
    with open(schema_path, "r") as f:
        schema = json.load(f)
    jsonschema.validate(instance=json_data, schema=schema)
