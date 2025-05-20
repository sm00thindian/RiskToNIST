"""Utility functions to generate JSON and HTML outputs."""

import json
import os
from jinja2 import Environment, FileSystemLoader

def generate_outputs(prioritized_controls):
    """Generate JSON and HTML outputs for prioritized controls.

    Args:
        prioritized_controls (list): List of tuples (control_id, control_data).
    """
    # Generate JSON output
    output_json = {
        "controls": [{"id": cid, "name": data["title"], "risks": data["risks"], "score": data["score"]}
                     for cid, data in prioritized_controls]
    }
    with open("outputs/controls.json", "w") as f:
        json.dump(output_json, f, indent=2)

    # Generate HTML output
    env = Environment(loader=FileSystemLoader("templates"))
    template = env.get_template("controls.html")
    html_content = template.render(controls=output_json["controls"])
    with open("outputs/controls.html", "w") as f:
        f.write(html_content)
