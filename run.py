import json
import logging
from src.data_ingestion import download_data
from src.data_processing import parse_cisa_kev, parse_kev_attack_mapping, parse_attack_mapping, parse_nist_catalog
from src.risk_calculation import calculate_control_risks
from src.output_generation import generate_json, generate_csv, generate_html

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def main():
    with open('config.json', 'r') as f:
        config = json.load(f)
    
    download_data(config['sources'])
    kev_data = parse_cisa_kev('data/cisa_kev.json', 'data/cisa_kev_schema.json')
    nist_controls = parse_nist_catalog('data/nist_sp800_53_catalog.json')
    
    control_to_risk, cve_details, total_cves = calculate_control_risks(kev_data)
    if not control_to_risk:
        logger.warning("No controls mapped to CVEs. Check attack_mapping.json and kev_attack_mapping.json.")
    
    generate_json(control_to_risk, nist_controls, cve_details, 'output.json')
    generate_csv(control_to_risk, nist_controls, cve_details, 'output.csv')
    generate_html(control_to_risk, nist_controls, cve_details, total_cves, 'output.html')

if __name__ == '__main__':
    main()
