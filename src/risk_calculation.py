from collections import defaultdict
from datetime import datetime, timedelta

def calculate_control_risks(kev_data):
    cve_to_techniques = parse_kev_attack_mapping('data/kev_attack_mapping.json')
    technique_to_controls = parse_attack_mapping('data/attack_mapping.json')
    
    control_to_cves = defaultdict(set)
    cve_details = {}
    
    current_date = datetime.now()
    urgency_threshold = current_date + timedelta(days=30)
    
    for item in kev_data:
        cve = item['cveID']
        cve_details[cve] = {
            'name': item['vulnerabilityName'],
            'description': item['shortDescription'],
            'dueDate': item['dueDate']
        }
        # Base risk score of 1, boosted to 1.5 if dueDate is within 30 days
        risk_score = 1.0
        if item['dueDate'] != 'N/A':
            try:
                due_date = datetime.strptime(item['dueDate'], '%Y-%m-%d')
                if due_date <= urgency_threshold:
                    risk_score = 1.5
            except ValueError:
                pass
        
        if cve in cve_to_techniques:
            techniques = cve_to_techniques[cve]
            for tech in techniques:
                if tech in technique_to_controls:
                    for control in technique_to_controls[tech]:
                        control_to_cves[control].add((cve, risk_score))
    
    # Sum risk scores for each control
    control_to_risk = {}
    for control, cve_set in control_to_cves.items():
        total_risk = sum(risk for _, risk in cve_set)
        control_to_risk[control] = {'total_risk': total_risk, 'cves': [cve for cve, _ in cve_set]}
    
    total_cves = len(kev_data)
    
    return control_to_risk, cve_details, total_cves
