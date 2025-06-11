# gap_identifier.py
"""Module to identify ATT&CK techniques without NIST control mappings."""

def identify_gaps(aws_data, attack_to_nist):
    """Identify ATT&CK techniques in AWS data without NIST control mappings.

    Includes techniques marked as `non_mappable` in `attack_mapping.json` and
    techniques in AWS data not present in the NIST mapping.

    Args:
        aws_data (dict): AWS mapping data with 'mapping_objects'.
        attack_to_nist (list): ATT&CK to NIST mappings.

    Returns:
        set: ATT&CK technique IDs not mapped to NIST controls.
    """
    # Techniques in AWS data
    aws_techniques = {mapping['attack_object_id'] for mapping in aws_data['mapping_objects'] 
                      if mapping.get('attack_object_id')}

    # Techniques with NIST control mappings
    mapped_techniques = {mapping['attack_id'] for mapping in attack_to_nist}

    # Load attack_mapping.json to include non_mappable techniques
    with open('attack_mapping.json', 'r') as f:
        attack_mapping = json.load(f)
    non_mappable_techniques = {mapping['attack_object_id'] for mapping in attack_mapping['mapping_objects'] 
                               if mapping['mapping_type'] == 'non_mappable' and mapping.get('attack_object_id')}

    # Combine non-mappable techniques and AWS techniques without NIST mappings
    return non_mappable_techniques | (aws_techniques - mapped_techniques)