import json
import pandas as pd
from jinja2 import Environment, FileSystemLoader
import os

def generate_json(prioritized_controls, output_path="outputs/controls.json"):
    """Generate JSON output with control details.

    Args:
        prioritized_controls (list): List of tuples (control_id, control_data).
        output_path (str): Path to save the JSON file.
    """
    output = [
        {
            "id": cid,
            "name": data["title"],
            "family": data["family_title"],
            "max_exploitation": data["max_exploitation"],
            "max_severity": data["max_severity"],
            "applicability": data["applicability"],
            "total_score": data["total_score"]
        }
        for cid, data in prioritized_controls
    ]
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        json.dump({"controls": output}, f, indent=2)
    print(f"Saved JSON to {output_path}")

def generate_csv(prioritized_controls, output_path="outputs/top_50_controls.csv"):
    """Generate CSV output with specified fields.

    Args:
        prioritized_controls (list): List of tuples (control_id, control_data).
        output_path (str): Path to save the CSV file.
    """
    data = [
        {
            "Control ID": cid,
            "Control Name": data["title"],
            "Control Family": data["family_title"],
            "max_exploitation": data["max_exploitation"],
            "max_severity": data["max_severity"],
            "applicability": data["applicability"],
            "total_score": data["total_score"]
        }
        for cid, data in prioritized_controls
    ]
    df = pd.DataFrame(data)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    df.to_csv(output_path, index=False)
    print(f"Saved CSV to {output_path}")

def generate_html(prioritized_controls, output_path="outputs/controls.html"):
    """Generate HTML output using a Jinja2 template.

    Args:
        prioritized_controls (list): List of tuples (control_id, control_data).
        output_path (str): Path to save the HTML file.
    """
    env = Environment(loader=FileSystemLoader("templates"))
    template = env.get_template("controls.html")
    html_content = template.render(controls=[
        {
            "id": cid,
            "name": data["title"],
            "family": data["family_title"],
            "max_exploitation": data["max_exploitation"],
            "max_severity": data["max_severity"],
            "applicability": data["applicability"],
            "total_score": data["total_score"]
        }
        for cid, data in prioritized_controls
    ])
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        f.write(html_content)
    print(f"Saved HTML to {output_path}")

def generate_attack_mappings_json(attack_mappings, output_path="outputs/attack_mappings.json"):
    """Generate pretty-printed JSON for ATT&CK to NIST 800-53 mappings.

    Args:
        attack_mappings (dict): Dictionary mapping ATT&CK techniques to NIST controls.
        output_path (str): Path to save the JSON file.
    """
    output = [
        {
            "technique_id": technique,
            "nist_controls": controls
        }
        for technique, controls in attack_mappings.items()
    ]
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        json.dump({"mappings": output}, f, indent=2)
    print(f"Saved ATT&CK mappings to {output_path}")

def generate_outputs(prioritized_controls, attack_mappings=None):
    """Generate JSON, CSV, HTML, and ATT&CK mappings outputs.

    Args:
        prioritized_controls (list): List of tuples (control_id, control_data).
        attack_mappings (dict, optional): ATT&CK to NIST control mappings.
    """
    generate_json(prioritized_controls)
    generate_csv(prioritized_controls)
    generate_html(prioritized_controls)
    if attack_mappings:
        generate_attack_mappings_json(attack_mappings)