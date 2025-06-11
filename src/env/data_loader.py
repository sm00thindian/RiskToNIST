# data_loader.py
"""Module to load AWS and ATT&CK-to-NIST mapping data from JSON files."""
import json

def load_aws_data(file_path):
    """Load AWS mapping data from a JSON file.

    Args:
        file_path (str): Path to the AWS JSON file.

    Returns:
        dict: Parsed AWS mapping data.

    Raises:
        FileNotFoundError: If the file does not exist.
        json.JSONDecodeError: If the file is not valid JSON.
    """
    with open(file_path, 'r') as f:
        return json.load(f)

def load_attack_to_nist_mapping(file_path):
    """Load ATT&CK to NIST mapping from a JSON file.

    Parses `attack_mapping.json` format with `mapping_objects` containing
    `attack_object_id`, `capability_id`, `capability_description`, `capability_group`,
    and `mapping_type`. Converts to list of {'attack_id': str, 'nist_controls': list}.

    Args:
        file_path (str): Path to the mapping JSON file.

    Returns:
        list: List of {'attack_id': str, 'nist_controls': list of {'id': str, 'name': str, 'family': str}}.

    Raises:
        FileNotFoundError: If the file does not exist.
        json.JSONDecodeError: If the file is not valid JSON.
    """
    with open(file_path, 'r') as f:
        data = json.load(f)

    # Organize mappings by attack_id
    attack_mappings = {}
    for mapping in data['mapping_objects']:
        attack_id = mapping.get('attack_object_id')
        if not attack_id:
            continue
        if mapping['mapping_type'] == 'mitigates' and mapping.get('capability_id'):
            control = {
                'id': mapping['capability_id'],
                'name': mapping['capability_description'],
                'family': mapping['capability_group']
            }
            if attack_id not in attack_mappings:
                attack_mappings[attack_id] = {'attack_id': attack_id, 'nist_controls': []}
            attack_mappings[attack_id]['nist_controls'].append(control)

    return list(attack_mappings.values())