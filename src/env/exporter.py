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
    # Sort data by risk_level in descending order, then by control ID for stability
    sorted_data = sorted(data, key=lambda x: (-x['risk_level'], x['id']))

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
            .nested-table { width: 100%; border-collapse: collapse; }
            .nested-table td { border: none; padding: 4px; }
            p { line-height: 1.6; }
        </style>
    </head>
    <body>
        <h1>Prioritized NIST 800-53 Controls for AWS Workloads</h1>
        <p>
            This report prioritizes NIST 800-53 controls for AWS workloads based on risk levels derived from associated MITRE ATT&CK techniques and their mitigations in AWS services. 
            <strong>Risk Level</strong> (0–3) indicates the criticality of implementing each control, where:
            <ul>
                <li><strong>0</strong>: No mitigation or low risk, minimal impact.</li>
                <li><strong>1</strong>: Minimal mitigation, moderate risk requiring attention.</li>
                <li><strong>2</strong>: Partial mitigation, high risk with significant exposure.</li>
                <li><strong>3</strong>: Significant mitigation, critical risk requiring urgent implementation.</li>
            </ul>
            Risk levels are determined by the minimum mitigation level of associated ATT&CK techniques, weighted by the effectiveness of AWS services (significant, partial, minimal, or none).
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
            {% for control in sorted_data %}
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
            This table provides detailed information for each NIST 800-53 control, including its family, risk level, and associated MITRE ATT&CK techniques with AWS mitigations. 
            Controls are sorted by risk level (highest first) to prioritize critical vulnerabilities. 
            Some ATT&CK techniques may lack mitigation details if no AWS-specific mitigations are defined in the input data, indicating they are unmapped or not mitigated by AWS services.
        </p>
        <table>
            <tr>
                <th>Control ID</th>
                <th>Control Name</th>
                <th>Family</th>
                <th>Risk Level</th>
                <th>Associated ATT&CK Techniques</th>
            </tr>
            {% for control in sorted_data %}
            <tr id="{{ control.id }}">
                <td>{{ control.id }}</td>
                <td>{{ control.name }}</td>
                <td>{{ FAMILY_MAPPING.get(control.family, control.family) }}</td>
                <td>{{ control.risk_level }}</td>
                <td>
                    <table class="nested-table">
                        {% for tech in control.associated_techniques %}
                        <tr>
                            <td>{{ tech.technique_id }}</td>
                            <td>
                                {% if tech.mitigations %}
                                <ul>
                                    {% for mitigation in tech.mitigations %}
                                    <li>{{ mitigation.aws_service }} ({{ mitigation.score_category }}, {{ mitigation.score_value }})</li>
                                    {% endfor %}
                                </ul>
                                {% else %}
                                No AWS mitigations defined
                                {% endif %}
                            </td>
                        </tr>
                        {% endfor %}
                    </table>
                </td>
            </tr>
            {% endfor %}
        </table>
    </body>
    </html>
    """)
    html_content = template.render(sorted_data=sorted_data, FAMILY_MAPPING=FAMILY_MAPPING)
    with open(file_path, 'w') as f:
        f.write(html_content)
