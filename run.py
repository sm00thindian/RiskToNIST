import json
from src.data_ingestion import download_data
from src.data_processing import parse_cisa_kev, parse_kev_attack_mapping, parse_attack_mapping, parse_nist_catalog, load_satisfied_controls
from src.risk_calculation import calculate_control_risks
from src.output_generation import generate_json, generate_csv, generate_html

def main():
    with open('config.json', 'r') as f:
        config = json.load(f)
    
    download_data(config['sources'])
    kev_cves = parse_cisa_kev('data/cisa_kev.csv')
    cve_to_techniques = parse_kev_attack_mapping('data/kev_attack_mapping.json')
    technique_to_controls = parse_attack_mapping('data/attack_mapping.json')
    nist_controls = parse_nist_catalog('data/nist_sp800_53_catalog.json')
    satisfied_controls = load_satisfied_controls('satisfied_controls.txt')
    
    control_to_risk, covered_cves, total_cves = calculate_control_risks(kev_cves, cve_to_techniques, technique_to_controls, satisfied_controls)
    
    generate_json(control_to_risk, nist_controls, 'output.json')
    generate_csv(control_to_risk, nist_controls, 'output.csv')
    generate_html(control_to_risk, nist_controls, covered_cves, total_cves, 'output.html')

if __name__ == '__main__':
    main()
