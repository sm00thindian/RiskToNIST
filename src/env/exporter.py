# exporter.py
"""Module to export prioritized NIST controls to CSV, JSON, and HTML formats."""
import csv
import json
from jinja2 import Template

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
            writer.writerow([control['id'], control['name'], control['family'], control['risk_level']])

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
        <title>Prioritized NIST Controls</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            h1, h2, h3, h4 { color: #333; }
            table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
            th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
            th { background-color: #4CAF50; color: white; }
            tr:nth-child(even) { background-color: #f2f2f2; }
            tr:hover { background-color: #ddd; }
            a { color: #0066cc; text-decoration: none; }
            a:hover { text-decoration: underline; }
            .details { margin-top: 20px; padding: 10px; border: 1px solid #ddd; background-color: #fafafa; }
        </style>
    </head>
    <body>
        <h1>Prioritized NIST 800-53 Controls</h1>
        <table>
            <tr>
                <th>Control ID</th>
                <th>Control Name</th>
                <th>Family Name</th>
                <th>Risk Level</th>
                <th>Details</th>
            </tr>
            {% for control in data %}
            <tr>
                <td>{{ control.id }}</td>
                <td>{{ control.name }}</td>
                <td>{{ control.family }}</td>
                <td>{{ control.risk_level }}</td>
                <td><a href="#{{ control.id }}">View Details</a></td>
            </tr>
            {% endfor %}
        </table>
        <h2>Detailed Control Information</h2>
        {% for control in data %}
        <div class="details" id="{{ control.id }}">
            <h3>{{ control.id }}: {{ control.name }}</h3>
            <p><strong>Family:</strong> {{ control.family }}</p>
            <p><strong>Risk Level:</strong> {{ control.risk_level }}</p>
            <h4>Associated ATT&CK Techniques:</h4>
            <ul>
                {% for tech in control.associated_techniques %}
                <li>{{ tech.technique_id }}:
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
    html_content = template.render(data=data)
    with open(file_path, 'w') as f:
        f.write(html_content)