import json
from jsonschema import validate, ValidationError
from datetime import datetime
from collections import defaultdict

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
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
        
        # Check for expected structure
        if 'mapping_objects' not in data:
            raise ValueError("Invalid KEV ATT&CK mapping JSON structure: missing 'mapping_objects'")
        
        # Build CVE to techniques mapping
        cve_to_techniques = defaultdict(list)
        for obj in data['mapping_objects']:
            cve = obj.get('capability_id')
            technique = obj.get('attack_object_id')
            if cve and technique:
                cve_to_techniques[cve].append(technique)
        
        if not cve_to_techniques:
            raise ValueError("No valid CVE-to-technique mappings found in KEV ATT&CK JSON")
        
        return dict(cve_to_techniques)
    
    except json.JSONDecodeError as e:
        print(f"Invalid JSON in KEV ATT&CK mapping file: {e}")
        raise
    except KeyError as e:
        print(f"Unexpected structure in KEV ATT&CK mapping JSON: missing key {e}")
        raise

def parse_attack_mapping(file_path):
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
        
        # Validate structure: expect dict mapping techniques to lists of controls
        if not isinstance(data, dict):
            raise ValueError("Invalid ATT&CK mapping JSON: expected a dictionary")
        
        for technique, controls in data.items():
            if not isinstance(controls, list):
                raise ValueError(f"Invalid ATT&CK mapping JSON: controls for technique {technique} must be a list")
            for control in controls:
                if not isinstance(control, str):
                    raise ValueError(f"Invalid ATT&CK mapping JSON: control {control} for technique {technique} must be a string")
        
        if not data:
            raise ValueError("No valid technique-to-control mappings found in ATT&CK JSON")
        
        return data
    
    except json.JSONDecodeError as e:
        print(f"Invalid JSON in ATT&CK mapping file: {e}")
        raise
    except KeyError as e:
        print(f"Unexpected structure in ATT&CK mapping JSON: missing key {e}")
        raise

def parse_nist_catalog(file_path):
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
        
        # Check for expected structure
        if 'catalog' not in data or 'groups' not in data['catalog']:
            raise ValueError("Invalid NIST SP 800-53 JSON structure: missing 'catalog' or 'groups'")
        
        # Extract controls from groups
        controls_dict = {}
        for group in data['catalog']['groups']:
            group_title = group.get('title', 'Unknown')
            if 'controls' in group:
                for control in group['controls']:
                    control_id = control.get('id')
                    if control_id:
                        controls_dict[control_id] = {
                            'title': control.get('title', 'N/A'),
                            'family': group_title
                        }
        
        if not controls_dict:
            raise ValueError("No controls found in NIST SP 800-53 JSON")
        
        return controls_dict
    
    except json.JSONDecodeError as e:
        print(f"Invalid JSON in NIST catalog file: {e}")
        raise
    except KeyError as e:
        print(f"Unexpected structure in NIST catalog JSON: missing key {e}")
        raise
