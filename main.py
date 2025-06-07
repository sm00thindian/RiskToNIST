import json
import logging
import os
from datetime import datetime, timedelta
import pandas as pd
from jinja2 import Environment, FileSystemLoader
from utils.download import download_datasets
from utils.parse import parse_all_datasets
from utils.map_risks import map_risks_to_controls, normalize_and_prioritize

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def load_nvd_api_key():
    """Load NVD API key from api_keys.json.

    Returns:
        str: API key if found, None otherwise.
    """
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
    """Load configuration from config.json.

    Returns:
        dict: Configuration dictionary.
    """
    try:
        with open('config.json', 'r') as f:
            config = json.load(f)
            logging.info("Successfully loaded configuration")
            return config
    except Exception as e:
        logging.error(f"Failed to load config: {e}")
        return {}

def serialize_datetime(obj):
    """Custom JSON serializer for datetime objects.

    Args:
        obj: Object to serialize.

    Returns:
        str: ISO-formatted string for datetime objects.

    Raises:
        TypeError: If object is not serializable.
    """
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Object of type {type(obj)} is not JSON serializable")

def write_outputs(prioritized_controls, output_dir, weights):
    """Write prioritized controls to JSON, CSV, and professional HTML outputs.

    Args:
        prioritized_controls (list): List of (control_id, details) tuples.
        output_dir (str): Directory to save output files.
        weights (dict): Weighting factors for scoring.
    """
    try:
        os.makedirs(output_dir, exist_ok=True)

        # JSON output
        controls_dict = {cid: details for cid, details in prioritized_controls}
        json_path = os.path.join(output_dir, 'controls.json')
        with open(json_path, 'w') as f:
            json.dump(controls_dict, f, indent=2, default=serialize_datetime)
        logging.info(f"Wrote JSON output to {json_path}")

        # CSV output (top 50)
        top_50 = prioritized_controls[:50]
        csv_data = []
        current_date = datetime.now()
        recent_threshold = current_date - timedelta(days=90)
        for cid, details in top_50:
            risk_contexts = details['risk_contexts']
            avg_priority = sum(
                weights["exploitation"] * float(ctx.get('exploitation_score', 0.0)) +
                weights["severity"] * float(ctx.get('impact_score', 0.0)) +
                weights["applicability"] * float(details.get('applicability', 7.0))
                for ctx in risk_contexts
            ) / len(risk_contexts) if risk_contexts else 0.0
            top_risks = [
                f"{ctx['cve_id']} ({ctx['exploitation_score']:.2f})"
                for ctx in sorted(risk_contexts, key=lambda x: x.get('exploitation_score', 0.0), reverse=True)[:3]
                if ctx['cve_id']
            ]
            unique_cwes = len(set(ctx.get('cwe', '') for ctx in risk_contexts if ctx.get('cwe')))
            recent_count = sum(
                1 for ctx in risk_contexts
                if ctx.get('published_date') and ctx['published_date'] >= recent_threshold
            )
            source_diversity = len(set(ctx['source'] for ctx in risk_contexts))
            maturity_order = {"ATTACKED": 3, "PROOF_OF_CONCEPT": 2, "UNREPORTED": 1}
            max_maturity = max(
                (maturity_order.get(ctx.get('exploit_maturity', 'UNREPORTED'), 1) for ctx in risk_contexts),
                default=1
            )
            max_maturity = next(k for k, v in maturity_order.items() if v == max_maturity)
            csv_data.append({
                'Control ID': cid,
                'Title': details['title'],
                'Control Family': details.get('family_title', 'Unknown'),
                'Priority Score': round(details['total_score'], 2),
                'Average Priority Score': round(avg_priority, 2),
                'Max Exploitation Score': round(details['max_exploitation'], 2),
                'Max Impact Score': round(details['max_severity'], 2),
                'Max Exploit Maturity': max_maturity,
                'Risk Count': len(risk_contexts),
                'Recent Risk Count': recent_count,
                'CISA KEV Count': sum(1 for ctx in risk_contexts if ctx['source'] == 'cisa_kev'),
                'NVD Count': sum(1 for ctx in risk_contexts if ctx['source'].startswith('nvd_')),
                'Attack Mapping Count': sum(1 for ctx in risk_contexts if ctx['source'] == 'kev_attack'),
                'Source Diversity': source_diversity,
                'Top Risk IDs': ', '.join(top_risks),
                'Unique CWEs': unique_cwes
            })
        df = pd.DataFrame(csv_data)
        csv_path = os.path.join(output_dir, 'top_50_controls.csv')
        df.to_csv(csv_path, index=False)
        logging.info(f"Wrote CSV output to {csv_path}")

        # HTML output using Jinja2 template
        template_dir = os.path.join(os.path.dirname(__file__), 'templates')
        os.makedirs(template_dir, exist_ok=True)
        template_path = os.path.join(template_dir, 'controls.html')
        if not os.path.exists(template_path):
            with open(template_path, 'w') as f:
                f.write('''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>NIST Controls Prioritization Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background-color: #f4f4f9; }
        h1 { color: #333; text-align: center; }
        .report-info { text-align: center; color: #666; margin-bottom: 20px; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; background-color: #fff; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background-color: #4CAF50; color: white; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        tr:hover { background-color: #f1f1f1; }
        .footer { text-align: center; margin-top: 40px; color: #666; font-size: 0.9em; }
    </style>
</head>
<body>
    <h1>NIST Controls Prioritization Report</h1>
    <div class="report-info">
        <p>Generated on: {{ current_date }}</p>
        <p>Data Period: {{ data_period }}</p>
    </div>
    <table>
        <thead>
            <tr>
                <th>Control ID</th>
                <th>Title</th>
                <th>Control Family</th>
                <th>Priority Score</th>
                <th>Average Priority Score</th>
                <th>Max Exploitation Score</th>
                <th>Max Impact Score</th>
                <th>Max Exploit Maturity</th>
                <th>Risk Count</th>
                <th>Recent Risk Count</th>
                <th>CISA KEV Count</th>
                <th>NVD Count</th>
                <th>Attack Mapping Count</th>
                <th>Source Diversity</th>
                <th>Top Risk IDs</th>
                <th>Unique CWEs</th>
            </tr>
        </thead>
        <tbody>
            {% for entry in csv_data %}
            <tr>
                <td>{{ entry['Control ID'] }}</td>
                <td>{{ entry['Title'] }}</td>
                <td>{{ entry['Control Family'] }}</td>
                <td>{{ entry['Priority Score']|round(2) }}</td>
                <td>{{ entry['Average Priority Score']|round(2) }}</td>
                <td>{{ entry['Max Exploitation Score']|round(2) }}</td>
                <td>{{ entry['Max Impact Score']|round(2) }}</td>
                <td>{{ entry['Max Exploit Maturity'] }}</td>
                <td>{{ entry['Risk Count'] }}</td>
                <td>{{ entry['Recent Risk Count'] }}</td>
                <td>{{ entry['CISA KEV Count'] }}</td>
                <td>{{ entry['NVD Count'] }}</td>
                <td>{{ entry['Attack Mapping Count'] }}</td>
                <td>{{ entry['Source Diversity'] }}</td>
                <td>{{ entry['Top Risk IDs'] }}</td>
                <td>{{ entry['Unique CWEs'] }}</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
    <div class="footer">
        <p>Generated by RiskToNIST &copy; {{ current_date|strftime('%Y') }}</p>
    </div>
</body>
</html>
                ''')
        env = Environment(loader=FileSystemLoader(template_dir))
        template = env.get_template('controls.html')
        current_date = datetime.now()
        data_period = f"{(current_date - timedelta(days=30*config.get('total_months', 6))).strftime('%Y-%m-%d')} to {get_last_saturday().strftime('%Y-%m-%d')}"
        html_content = template.render(csv_data=csv_data, current_date=current_date.strftime('%B %d, %Y'), data_period=data_period)
        html_path = os.path.join(output_dir, 'controls.html')
        with open(html_path, 'w') as f:
            f.write(html_content)
        logging.info(f"Wrote HTML output to {html_path}")

        logging.info("Completed writing outputs")
    except Exception as e:
        logging.error(f"Failed to write outputs: {e}")

def main():
    """Orchestrate the RiskToNIST process to map risks to NIST controls.

    Raises:
        ValueError: If no NVD API key is provided.
    """
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
        all_risks = parse_all_datasets(data_dir, attack_mappings, config)
        logging.info(f"Parsed risks from {len(all_risks)} sources")

        controls, control_details = map_risks_to_controls(all_risks, data_dir)
        prioritized_controls = normalize_and_prioritize(controls, weights)
        write_outputs(prioritized_controls, output_dir, weights)

        logging.info("Processing complete")
    except Exception as e:
        logging.error(f"Processing failed: {e}")

if __name__ == "__main__":
    main()
