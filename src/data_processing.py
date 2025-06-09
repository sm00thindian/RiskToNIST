import json
from jsonschema import validate, ValidationError
from datetime import datetime

def parse_cisa_kev(file_path, schema_path):
    try:
        with open(schema_path, 'r') as f:
            schema = json.load(f)
        with open(file_path, 'r') as f:
            data = json.load(f)
        validate(instance=data, schema=schema)
    except ValidationError as e:
        print(f"CISA KEV JSON validation failed: {e}")
        raise
    except json.JSONDecodeError as e:
        print(f"Invalid JSON in CISA KEV file: {e}")
        raise
    
    # Extract cveID, vulnerabilityName, shortDescription, dueDate
    return [{
        'cveID': item['cveID'],
        'vulnerabilityName': item.get('vulnerabilityName', 'N/A'),
        'shortDescription': item.get('shortDescription', 'N/A'),
        'dueDate': item.get('dueDate', 'N/A')
    } for item in data['vulnerabilities']]

def parse_kev_attack_mapping(file_path):
    with open(file_path, 'r') as f:
        data = json.load(f)
        # Expected: {"cve": ["T1234", "T5678"], ...}
        return data

def parse_attack_mapping(file_path):
    with open(file_path, 'r') as f:
        data = json.load(f)
        # Expected: {"technique": ["AC-1", "AC-2"], ...}
        return data

def parse_nist_catalog(file_path):
    with open(file_path, 'r') as f:
        data = json.load(f)
        # Expected: {"catalog": {"controls": [{"id": "AC-1", "title": "...", "family": "Access Control"}, ...]}}
        return {control['id']: {"title": control['title'], "family": control.get('family', 'Unknown')} for control in data['catalog']['controls']}
