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

def get_last_saturday():
    """Calculate the date of the last Saturday before today.

    Returns:
        datetime: Date of the last Saturday.
    """
    today = datetime.utcnow().replace(hour=23, minute=59, second=59, microsecond=999999)
    days_since_saturday = (today.weekday() + 1) % 7
    if days_since_saturday == 0:
        days_since_saturday = 7
    return today - timedelta(days=days_since_saturday)

def strftime_filter(dt, fmt):
    """Custom Jinja2 filter to format datetime objects.

    Args:
        dt: Datetime object or string to format.
        fmt (str): Format string for strftime.

    Returns:
        str: Formatted date string, or empty string if formatting fails.
    """
    try:
        if isinstance(dt, datetime):
            return dt.strftime(fmt)
        elif isinstance(dt, str):
            return datetime.strptime(dt, "%Y-%m-%dT%H:%M:%S").strftime(fmt)
        return ""
    except (ValueError, TypeError) as e:
        logging.warning(f"Failed to format datetime with format {fmt}: {e}")
        return ""

def write_outputs(prioritized_controls, output_dir, weights, config, total_risks, source_count, unmapped_techniques, validation_failures):
    """Write prioritized controls to JSON, CSV, and professional HTML outputs with summary metrics.

    Args:
        prioritized_controls (list): List of (control_id, details) tuples.
        output_dir (str): Directory to save output files.
        weights (dict): Weighting factors for scoring.
        config (dict): Configuration dictionary from config.json.
        total_risks (int): Total number of risks parsed.
        source_count (int): Number of sources processed.
        unmapped_techniques (int): Number of unmapped ATT&CK techniques/CWEs.
        validation_failures (int): Number of CVSS v4.0 validation failures.
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
                'Top Risk IDs': ', '.join(top_risks),
                'Unique CWEs': unique_cwes
            })
        df = pd.DataFrame(csv_data)
        csv_path = os.path.join(output_dir, 'top_50_controls.csv')
        df.to_csv(csv_path, index=False)
        logging.info(f"Wrote CSV output to {csv_path}")

        # HTML output using external Jinja2 template
        template_dir = os.path.join(os.path.dirname(__file__), 'templates')
        if not os.path.exists(template_dir):
            os.makedirs(template_dir)
        template_path = os.path.join(template_dir, 'controls.html')
        if not os.path.exists(template_path):
            logging.error(f"Template {template_path} not found. Please ensure controls.html exists in the templates directory.")
            return
        env = Environment(loader=FileSystemLoader(template_dir))
        env.filters['strftime'] = strftime_filter  # Add custom strftime filter
        template = env.get_template('controls.html')
        current_date = datetime.now()
        data_period = f"{(current_date - timedelta(days=30*config.get('sources', [{}])[0].get('total_months', 6))).strftime('%Y-%m-%d')} to {get_last_saturday().strftime('%Y-%m-%d')}"
        try:
            html_content = template.render(
                csv_data=csv_data,
                current_date=current_date,
                data_period=data_period,
                total_risks=total_risks,
                source_count=source_count,
                unmapped_techniques=unmapped_techniques,
                validation_failures=validation_failures
            )
            html_path = os.path.join(output_dir, 'controls.html')
            with open(html_path, 'w') as f:
                f.write(html_content)
            logging.info(f"Wrote HTML output to {html_path}")
        except Exception as e:
            logging.error(f"Failed to render HTML template: {e}")
            # Continue to ensure JSON and CSV outputs are not affected

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
        source_count = len(all_risks)
        total_risks = sum(len(risks) for risks in all_risks.values())
        logging.info(f"Parsed risks from {source_count} sources")

        controls, control_details = map_risks_to_controls(all_risks, data_dir)
        prioritized_controls = normalize_and_prioritize(controls, weights)

        # Extract summary metrics from logs
        unmapped_techniques = len([line for line in open('outputs/run.log') if "No NIST controls mapped for technique" in line])
        validation_failures = len([line for line in open('outputs/run.log') if "CVSS 4.0 validation failed" in line])

        write_outputs(prioritized_controls, output_dir, weights, config, total_risks, source_count, unmapped_techniques, validation_failures)

        logging.info("Processing complete")
    except Exception as e:
        logging.error(f"Processing failed: {e}")

if __name__ == "__main__":
    main()
