import json
import pandas as pd
from jinja2 import Environment, FileSystemLoader

def generate_json(prioritized_controls, output_path="outputs/controls.json"):
    """Generate JSON output with control details."""
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
    with open(output_path, "w") as f:
        json.dump({"controls": output}, f, indent=2)

def generate_csv(prioritized_controls, output_path="outputs/top_50_controls.csv"):
    """Generate CSV output with specified fields."""
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
    df.to_csv(output_path, index=False)

def generate_html(prioritized_controls, output_path="outputs/controls.html"):
    """Generate HTML output using a Jinja2 template."""
    env = Environment(loader=FileSystemLoader("templates"))
    template = env.get_template("controls.html")
    html_content = template.render(controls=[
        {
            "id": cid,
            "name": data["title"],
            "family": data["family_title"],
            "total_score": data["total_score"]
            # Add other fields to template if desired
        }
        for cid, data in prioritized_controls
    ])
    with open(output_path, "w") as f:
        f.write(html_content)

def generate_outputs(prioritized_controls):
    """Generate all output formats."""
    os.makedirs("outputs", exist_ok=True)
    generate_json(prioritized_controls)
    generate_csv(prioritized_controls)
    generate_html(prioritized_controls)