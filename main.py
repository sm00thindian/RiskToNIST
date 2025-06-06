import json
import logging
import os
from utils.download import download_datasets
from utils.parse import parse_all_datasets
from utils.map_risks import map_risks_to_controls, normalize_and_prioritize
import pandas as pd
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def load_nvd_api_key():
    """Load NVD API key from api_keys.json."""
    try:
        with open('api_keys.json', 'r') as f:
            keys = json.load(f)
            api_key = keys.get('NVD_API_KEY')
            if not api_key:
                raise ValueError("NVD_API_KEY not found in api_keys.json")
            logging.info("Loaded NVD_API_KEY from api_keys.json")
            return api_key
    except Exception as e:
        logging.error(f"Failed to load NVD_API_KEY: {e}")
        return None

def load_config():
    """Load configuration from config.json."""
    try:
        with open('config.json', 'r') as f:
            config = json.load(f)
            logging.info("Successfully loaded configuration")
            return config
    except Exception as e:
        logging.error(f"Failed to load config: {e}")
        return {}

def write_outputs(prioritized_controls, output_dir, weights):
    """Write prioritized controls to JSON, CSV, and HTML with source counts."""
    try:
        os.makedirs(output_dir, exist_ok=True)
        
        # JSON output
        controls_dict = {cid: details for cid, details in prioritized_controls}
        with open(os.path.join(output_dir, 'controls.json'), 'w') as f:
            json.dump(controls_dict, f, indent=2)
        logging.info(f"Wrote JSON output to {os.path.join(output_dir, 'controls.json')}")
        
        # CSV output (top 50)
        top_50 = prioritized_controls[:50]
        csv_data = [
            {
                'Control ID': cid,
                'Title': details['title'],
                'Priority Score': details['total_score'],
                'Risk Count': len(details['risk_contexts']),
                'CISA KEV Count': sum(1 for ctx in details['risk_contexts'] if ctx['source'] == 'cisa_kev'),
                'NVD Count': sum(1 for ctx in details['risk_contexts'] if ctx['source'].startswith('nvd_')),
                'Attack Mapping Count': sum(1 for ctx in details['risk_contexts'] if ctx['source'] == 'kev_attack')
            }
            for cid, details in top_50
        ]
        df = pd.DataFrame(csv_data)
        csv_path = os.path.join(output_dir, 'top_50_controls.csv')
        df.to_csv(csv_path, index=False)
        logging.info(f"Wrote CSV output to {csv_path}")
        
        # HTML output
        html_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>NIST Controls Prioritization</title>
            <style>
                table { border-collapse: collapse; width: 100%; }
                th, td { border: 1px solid black; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
            </style>
        </head>
        <body>
            <h2>NIST Controls Prioritization</h2>
            <table>
                <tr>
                    <th>Control ID</th>
                    <th>Title</th>
                    <th>Priority Score</th>
                    <th>Risk Count</th>
                    <th>CISA KEV Count</th>
                    <th>NVD Count</th>
                    <th>Attack Mapping Count</th>
                </tr>
        """
        for cid, details in top_50:
            html_content += f"""
                <tr>
                    <td>{cid}</td>
                    <td>{details['title']}</td>
                    <td>{details['total_score']:.2f}</td>
                    <td>{len(details['risk_contexts'])}</td>
                    <td>{sum(1 for ctx in details['risk_contexts'] if ctx['source'] == 'cisa_kev')}</td>
                    <td>{sum(1 for ctx in details['risk_contexts'] if ctx['source'].startswith('nvd_'))}</td>
                    <td>{sum(1 for ctx in details['risk_contexts'] if ctx['source'] == 'kev_attack')}</td>
                </tr>
            """
        html_content += """
            </table>
        </body>
        </html>
        """
        html_path = os.path.join(output_dir, 'controls.html')
        with open(html_path, 'w') as f:
            f.write(html_content)
        logging.info(f"Wrote HTML output to {html_path}")
        
        logging.info("Completed writing outputs")
    except Exception as e:
        logging.error(f"Failed to write outputs: {e}")

def main():
    """Main function to orchestrate the RiskToNIST process."""
    try:
        api_key = load_nvd_api_key()
        if not api_key:
            raise ValueError("No NVD API key provided")
        
        config = load_config()
        data_dir = config.get('data_dir', 'data')
        output_dir = config.get('output_dir', 'outputs')
        weights = config.get('weights', {'exploitation': 0.4, 'severity': 0.4, 'applicability': 0.2})
        
        logging.info("Starting dataset downloads")
        download_datasets(config, data_dir, force_refresh=False)
        logging.info("Completed dataset downloads")
        
        logging.info("Loading ATT&CK mappings from data")
        attack_mappings_path = os.path.join(data_dir, 'attack_mapping.json')
        with open(attack_mappings_path, 'r') as f:
            attack_mappings = json.load(f)
        logging.info(f"Loaded {len(attack_mappings.get('mapping_objects', []))} ATT&CK mappings")
        
        logging.info("Starting dataset parsing")
        all_risks = parse_all_datasets(data_dir, attack_mappings)
        logging.info(f"Parsed risks from {len(all_risks)} sources")
        
        controls, control_details = map_risks_to_controls(all_risks, data_dir)
        prioritized_controls = normalize_and_prioritize(controls, weights)
        write_outputs(prioritized_controls, output_dir, weights)
        
        logging.info("Processing complete")
    except Exception as e:
        logging.error(f"Processing failed: {e}")

if __name__ == "__main__":
    main()
