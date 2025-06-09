from collections import defaultdict

def calculate_control_risks(kev_cves, cve_to_techniques, technique_to_controls, satisfied_controls):
    control_to_cves = defaultdict(set)
    for cve in kev_cves:
        if cve in cve_to_techniques:
            techniques = cve_to_techniques[cve]
            for tech in techniques:
                if tech in technique_to_controls:
                    for control in technique_to_controls[tech]:
                        control_to_cves[control].add(cve)
    
    control_to_risk = {control: len(cves) for control, cves in control_to_cves.items() if control in satisfied_controls}
    covered_cves = set.union(*(control_to_cves[control] for control in satisfied_controls)) if satisfied_controls else set()
    total_cves = set(kev_cves)
    
    return control_to_risk, covered_cves, total_cves
