# exporter.py
"""Module to export prioritized NIST controls to CSV, JSON, and HTML formats."""
import csv
import json
from jinja2 import Template

# Mapping of NIST 800-53 family acronyms to full names
FAMILY_MAPPING = {
    'AC': 'Access Control',
    'CA': 'Security Assessment and Authorization',
    'CM': 'Configuration Management',
    'CP': 'Contingency Planning',
    'IA': 'Identification and Authentication',
    'MP': 'Media Protection',
    'RA': 'Risk Assessment',
    'SA': 'System and Services Acquisition',
    'SC': 'System and Communications Protection',
    'SI': 'System and Information Integrity',
    'SR': 'Supply Chain Risk Management'
}

def export_to_csv(data, file_path):
    """Export prioritized controls to a CSV file.

    Args:
        data (list): List of control dictionaries.
        file_path (str): Path to save the CSV file.
    """
    with open(file_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Control ID', 'Control Name', 'Family Name', 'Risk Level'])
        for control in data:
            writer.writerow([control['id'], control['name'], FAMILY_MAPPING.get(control['family'], control['family']), control['risk_level']])

def export_to_json(data, file_path):
    """Export prioritized controls to a JSON file with full details.

    Args:
        data (list): List of control dictionaries.
        file_path (str): Path to save the JSON file.
    """
    with open(file_path, 'w') as f:
        json.dump(data, f, indent=4)

def export_to_html(data, file_path):
    """Export prioritized controls to a styled HTML file with detailed sections.

    Args:
        data (list): List of control dictionaries.
        file_path (str): Path to save the HTML file.
    """
    template = Template("""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Prioritized NIST 800-53 Controls for AWS Workloads</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            h1, h2, h3 { color: #333; }
            table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
            th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
            th { background-color: #f2f2f2; }
            tr:nth-child(even) { background-color: #f9f9f9; }
            ul { margin: 0; padding-left: 20px; }
            p { line-height: 1.6; }
        </style>
    </head>
    <body>
        <h1>Prioritized NIST 800-53 Controls for AWS Workloads</h1>
        <p>
            This report prioritizes NIST 800-53 controls for AWS workloads based on risk levels derived from associated MITRE ATT&CK techniques and their mitigations in AWS services. 
            <strong>Risk Level</strong> (0–3) indicates the criticality of implementing each control, where:
            <ul>
                <li><strong>0</strong>: Low risk, minimal impact or well-mitigated by AWS services.</li>
                <li><strong>1</strong>: Moderate risk, some exposure requiring attention.</li>
                <li><strong>2</strong>: High risk, significant exposure or frequent attack vectors.</li>
                <li><strong>3</strong>: Critical risk, urgent implementation recommended due to severe impact.</li>
            </ul>
            Risk levels are calculated based on the severity, exploitability, and prevalence of ATT&CK techniques, weighted by the effectiveness of AWS mitigations (e.g., "significant" or "partial" protection).
        </p>

        <h2>Control Summary</h2>
        <table>
            <tr>
                <th>Control ID</th>
                <th>Control Name</th>
                <th>Family</th>
                <th>Risk Level</th>
                <th>Details</th>
            </tr>
            {% for control in data %}
            <tr>
                <td>{{ control.id }}</td>
                <td>{{ control.name }}</td>
                <td>{{ FAMILY_MAPPING.get(control.family, control.family) }}</td>
                <td>{{ control.risk_level }}</td>
                <td><a href="#{{ control.id }}">View Details</a></td>
            </tr>
            {% endfor %}
        </table>

        <h2>Detailed Control Information</h2>
        <p>
            This section provides detailed information for each NIST 800-53 control, including its family, risk level, and associated MITRE ATT&CK techniques with AWS mitigations. 
            Use this report to prioritize security controls for your AWS workloads, focusing on higher risk levels (2–3) to address critical vulnerabilities. 
            Each control links to its corresponding entry in the summary table above.
        </p>
        {% for control in data %}
        <div id="{{ control.id }}">
            <h3>{{ control.id }}: {{ control.name }}</h3>
            <p><strong>Family:</strong> {{ FAMILY_MAPPING.get(control.family, control.family) }}</p>
            <p><strong>Risk Level:</strong> {{ control.risk_level }}</p>
            <p><strong>Associated ATT&CK Techniques:</strong></p>
            <ul>
                {% for tech in control.associated_techniques %}
                <li>
                    {{ tech.technique_id }}:
                    <ul>
                        {% for mitigation in tech.mitigations %}
                        <li>{{ mitigation.aws_service }} ({{ mitigation.score_category }}, {{ mitigation.score_value }})</li>
                        {% endfor %}
                    </ul>
                </li>
                {% endfor %}
            </ul>
        </div>
        {% endfor %}
    </body>
    </html>
    """)
    html_content = template.render(data=data, FAMILY_MAPPING=FAMILY_MAPPING)
    with open(file_path, 'w') as f:
        f.write(html_content)
