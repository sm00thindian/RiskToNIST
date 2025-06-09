import json

def parse_cisa_kev(file_path):
    with open(file_path, 'r') as f:
        data = json.load(f)
        # Expected: {"vulnerabilities": [{"cveID": "CVE-2023-1234", ...}, ...]}
        return [item['cveID'] for item in data['vulnerabilities']]

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
