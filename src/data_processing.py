import csv
import json

def parse_cisa_kev(file_path):
    with open(file_path, 'r') as f:
        reader = csv.DictReader(f)
        return [row['cveID'] for row in reader]

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
        # Expected: {"controls": [{"id": "AC-1", "title": "..."}, ...]}
        return {control['id']: control['title'] for control in data['controls']}

def load_satisfied_controls(file_path):
    with open(file_path, 'r') as f:
        return [line.strip() for line in f if line.strip()]
