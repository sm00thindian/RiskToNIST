# risk_prioritizer.py
"""Module to prioritize NIST 800-53 controls based on risk from AWS mitigations."""
from collections import defaultdict

def prioritize_controls(aws_data, attack_to_nist):
    """Prioritize NIST controls based on risk derived from AWS mitigations.

    Risk level is the minimum mitigation level of associated ATT&CK techniques:
    - 0: No mitigation
    - 1: Minimal
    - 2: Partial
    - 3: Significant
    Adds mitigation coverage (proportion of mitigated techniques) and technique count for prioritization.

    Args:
        aws_data (dict): AWS mapping data with 'mapping_objects'.
        attack_to_nist (list): ATT&CK to NIST mappings.

    Returns:
        list: Prioritized list of control dictionaries sorted by risk level.
    """
    # Define score values
    score_values = {'significant': 3, 'partial': 2, 'minimal': 1}

    # Calculate mitigation levels for each technique
    technique_mitigations = defaultdict(list)
    for mapping in aws_data['mapping_objects']:
        if mapping.get('status') == 'complete' and mapping.get('attack_object_id'):
            score = mapping.get('score_value', '').lower()
            if score in score_values:
                technique_mitigations[mapping['attack_object_id']].append(score_values[score])

    technique_mitigation_level = {tech: max(scores) if scores else 0 
                                  for tech, scores in technique_mitigations.items()}

    # Map NIST controls to techniques and store control details
    control_to_techniques = defaultdict(list)
    nist_controls = {}
    for mapping in attack_to_nist:
        for control in mapping['nist_controls']:
            control_id = control['id']
            control_to_techniques[control_id].append(mapping['attack_id'])
            if control_id not in nist_controls:
                nist_controls[control_id] = control

    # Calculate risk levels and mitigation coverage
    control_risk_levels = {}
    control_mitigation_coverage = {}
    control_technique_counts = {}
    for control_id, techniques in control_to_techniques.items():
        min_mitigation = min(technique_mitigation_level.get(tech, 0) for tech in techniques)
        control_risk_levels[control_id] = min_mitigation
        # Count mitigated techniques (non-zero mitigation level)
        mitigated_count = sum(1 for tech in techniques if technique_mitigation_level.get(tech, 0) > 0)
        total_count = len(techniques)
        control_mitigation_coverage[control_id] = mitigated_count / total_count if total_count > 0 else 0
        control_technique_counts[control_id] = total_count

    # Build prioritized list
    prioritized_controls = []
    for control_id in sorted(control_risk_levels.keys()):
        control = nist_controls[control_id]
        associated_techniques = []
        for tech in control_to_techniques[control_id]:
            mitigations = [
                {
                    'aws_service': m.get('capability_description', 'Unknown Service'),
                    'score_category': m.get('score_category', 'Unknown'),
                    'score_value': m.get('score_value', 'Unknown')
                }
                for m in aws_data['mapping_objects'] if m.get('attack_object_id') == tech
            ]
            associated_techniques.append({
                'technique_id': tech,
                'mitigations': mitigations
            })
        prioritized_controls.append({
            'id': control['id'],
            'name': control['name'],
            'family': control['family'],
            'risk_level': control_risk_levels[control_id],
            'mitigation_coverage': control_mitigation_coverage[control_id],
            'technique_count': control_technique_counts[control_id],
            'associated_techniques': associated_techniques
        })
    return prioritized_controls
