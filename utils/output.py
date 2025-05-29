import json
import csv
import os
import logging
from jinja2 import Environment, FileSystemLoader

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def write_outputs(prioritized_controls, data_dir):
    """Write prioritized controls to JSON, CSV, and HTML files.

    Args:
        prioritized_controls (list): List of tuples (control_id, control_details).
        data_dir (str): Directory containing data files (used to find project root).
    """
    # Set output directory as peer to data_dir
    project_root = os.path.dirname(data_dir)  # e.g., /Users/p1krw01/Projects/RiskToNIST
    output_dir = os.path.join(project_root, "outputs")
    os.makedirs(output_dir, exist_ok=True)
    logging.debug(f"Writing outputs to directory: {output_dir}")
    
    # Write JSON output
    json_path = os.path.join(output_dir, "controls.json")
    try:
        controls_dict = {control_id: details for control_id, details in prioritized_controls}
        with open(json_path, "w") as f:
            json.dump(controls_dict, f, indent=2)
        logging.info(f"Wrote JSON output to {json_path}")
    except Exception as e:
        logging.error(f"Failed to write JSON to {json_path}: {e}")
    
    # Write CSV output
    csv_path = os.path.join(output_dir, "top_50_controls.csv")
    try:
        with open(csv_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Control ID", "Title", "Family", "Total Score", "Max Exploitation", "Max Severity", "Applicability"])
            for control_id, details in prioritized_controls[:50]:  # Top 50
                writer.writerow([
                    control_id,
                    details.get("title", ""),
                    details.get("family_title", ""),
                    round(details.get("total_score", 0.0), 2),
                    round(details.get("max_exploitation", 0.0), 2),
                    round(details.get("max_severity", 0.0), 2),
                    round(details.get("applicability", 0.0), 2)
                ])
        logging.info(f"Wrote CSV output to {csv_path}")
    except Exception as e:
        logging.error(f"Failed to write CSV to {csv_path}: {e}")
    
    # Write HTML output
    html_path = os.path.join(output_dir, "controls.html")
    template_path = os.path.join(project_root, "templates", "controls.html")
    try:
        if not os.path.exists(template_path):
            logging.warning(f"Template {template_path} not found, skipping HTML output")
            return
        env = Environment(loader=FileSystemLoader(os.path.join(project_root, "templates")))
        template = env.get_template("controls.html")
        html_content = template.render(controls=prioritized_controls)
        with open(html_path, "w") as f:
            f.write(html_content)
        logging.info(f"Wrote HTML output to {html_path}")
    except Exception as e:
        logging.error(f"Failed to write HTML to {html_path}: {e}")

if __name__ == "__main__":
    # Example usage for testing
    sample_controls = [
        ("AC-2", {"title": "Account Management", "family_title": "Access Control", "total_score": 9.8, "max_exploitation": 10.0, "max_severity": 10.0, "applicability": 7.0}),
        ("SI-2", {"title": "Flaw Remediation", "family_title": "System and Information Integrity", "total_score": 8.0, "max_exploitation": 8.0, "max_severity": 8.0, "applicability": 7.0})
    ]
    write_outputs(sample_controls, "data")