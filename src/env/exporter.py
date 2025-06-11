# exporter.py
"""Module to export prioritized NIST controls to CSV, JSON, and HTML formats."""
import csv
import json
import os
import zipfile
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
        writer.writerow(['Control ID', 'Control Name', 'Family Name', 'Risk Level', 'Mitigation Coverage'])
        for control in data:
            coverage = f"{control['mitigation_coverage']*100:.1f}% ({sum(1 for tech in control['associated_techniques'] if tech['mitigations'])}/{control['technique_count']})"
            writer.writerow([control['id'], control['name'], FAMILY_MAPPING.get(control['family'], control['family']), control['risk_level'], coverage])

def export_to_json(data, file_path):
    """Export prioritized controls to a JSON file with full details.

    Args:
        data (list): List of control dictionaries.
        file_path (str): Path to save the JSON file.
    """
    with open(file_path, 'w') as f:
        json.dump(data, f, indent=4)

def export_to_html(data, output_dir):
    """Export prioritized controls to a summary HTML file, per-control detail HTML files, and a ZIP archive.

    Args:
        data (list): List of control dictionaries.
        output_dir (str): Directory to save the HTML files and ZIP archive.
    """
    # Sort data by risk_level (descending), mitigation_coverage (descending), technique_count (descending), then control ID
    sorted_data = sorted(data, key=lambda x: (-x['risk_level'], -x['mitigation_coverage'], -x['technique_count'], x['id']))

    # Common CSS
    common_style = """
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1, h2, h3 { color: #333; }
        table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; vertical-align: top; }
        th { background-color: #f2f2f2; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        .nested-table { width: 100%; border-collapse: collapse; }
        .nested-table td { border: none; padding: 4px; vertical-align: top; }
        p { line-height: 1.6; }
        .comment { cursor: pointer; color: #0066cc; }
        .comment:hover { text-decoration: underline; }
        .tooltip { display: none; position: absolute; background: #f9f9f9; border: 1px solid #ddd; padding: 5px; max-width: 300px; }
        .comment:hover .tooltip { display: block; }
        footer { margin-top: 20px; font-size: 0.9em; color: #666; }
    """

    # Summary page template
    summary_template = Template("""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Prioritized NIST 800-53 Controls for AWS Workloads - Summary</title>
        <style>{{ style }}</style>
    </head>
    <body>
        <h1>Prioritized NIST 800-53 Controls for AWS Workloads - Summary</h1>
        <p>
            This report prioritizes NIST 800-53 controls for AWS workloads based on risk levels derived from associated MITRE ATT&CK techniques and their mitigations in AWS services. 
            <strong>Risk Level</strong> (0–3) indicates the criticality of implementing each control, where:
            <ul>
                <li><strong>0</strong>: No mitigation for at least one associated technique, indicating high risk.</li>
                <li><strong>1</strong>: Minimal mitigation, moderate risk requiring attention.</li>
                <li><strong>2</strong>: Partial mitigation, high risk with significant exposure.</li>
                <li><strong>3</strong>: Significant impact, critical risk mitigated by AWS services.</li>
            </ul>
            Risk levels are determined by the minimum mitigation level of associated ATT&CK techniques, weighted by the effectiveness of AWS services (significant impact, partial, minimal, or none). 
            Within the same risk level, controls are prioritized by mitigation percentage (proportion of mitigated techniques) and number of associated techniques. 
            Click "Details" to view detailed mitigation information for each control. 
            All HTML reports are also available as a single ZIP file: <a href="aws_data.zip">aws_data.zip</a>.
        </p>

        <h2>Control List</h2>
        <table>
            <tr>
                <th>Control ID</th>
                <th>Control Name</th>
                <th>Family</th>
                <th>Risk</th>
                <th>Mitigation</th>
                <th>Details</th>
            </tr>
            {% for control in data %}
            <tr>
                <td>{{ control.id }}</td>
                <td>{{ control.name }}</td>
                <td>{{ FAMILY_MAPPING.get(control.family, '') }}</td>
                <td>{{ control.risk_level }}</td>
                <td>{{ (control.mitigation_coverage*100)|round(1) }}% ({{ control.associated_data|selectattr('mitigations')|list|length }}/{{ control.data_length }})</td>
                <td><a href="data_details_{{ control.id }}.html">View Details</a></td>
            </tr>
            {% endfor %}
        </table>
        <footer>
            Generated using AWS Mapping v12/12/2024 and MITRE ATT&CK v16.1
        </footer>
    </body>
    </html>
    """)

    # Per-control detail page template
    detail_template = Template("""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Prioritized NIST 800-53 Control: {{ control.id }} - {{ control.name }}</title>
        <style>{{ style }}</style>
    </head>
    <body>
        <h1>Prioritized NIST 800-53 Control: {{ control.id }} - {{ control.name }}</h1>
        <p>
            This page provides detailed information for NIST 800-53 control {{ control.id }}, including its family, risk level, mitigation percentage, and associated MITRE ATT&CK techniques with AWS mitigations. 
            Return to the <a href="data_summary.html">Summary page</a> to view all controls. 
            Techniques with "No AWS mitigations defined" indicate no specific AWS service mappings in the input data, suggesting higher risk due to unmitigated vulnerabilities. 
            Assess these techniques further based on your environment’s exposure and the technique’s severity. 
            Click on mitigation comments for additional details.
            All HTML reports are also available as a single ZIP file: <a href="aws_data.zip">aws_data.zip</a>.
        </p>
        <table>
            <tr>
                <th>Control ID</th>
                <th>Control Name</th>
                <th>Family</th>
                <th>Risk Level</th>
                <th>Mitigation</th>
                <th>Associated ATT&CK Techniques</th>
            </tr>
            <tr id="{{ control.id }}">
                <td>{{ control.id }}</td>
                <td>{{ control.name }}</td>
                <td>{{ FAMILY_MAPPING.get(control.family, '') }}</td>
                <td>{{ control.risk_level }}</td>
                <td>{{ (control.mitigation_coverage*100)|round(1) }}% ({{ control.associated_data|selectattr('mitigations')|list|length }}/{{ control.data_length }})</td>
                <td>
                    <table class="nested-table">
                        {% for tech in control.associated_data %}
                        <tr>
                            <td>{{ tech.data_id }}: {{ tech.data_name | default('') }}</td>
                            <td>
                                {% if tech.mitigations %}
                                <ul>
                                    {% for mitigation in tech.mitigations %}
                                    <li>
                                        {{ mitigation.file }} ({{ mitigation.reason}}, {{ mitigation.level}})
                                        {% if mitigation.comment %}
                                        <span class="comment" title="{{ mitigation.comment | e }}">{{ mitigation.comment[:100] | e }}{% if mitigation.comment|length > 100 %}...{% endif %}
                                            <span class="tooltip">{{ mitigation.comment | e }}</span>
                                        </span>
                                        {% endif %}
                                        {% if mitigation.files %}
                                        <br>Files:
                                        <ul>
                                            {% for ref in mitigation.files %}
                                            <li><a href="{{ ref | e }}" target="_blank">{{ ref | truncate(50) | e }}</a></li>
                                            {% endfor %}
                                        </ul>
                                        {% else %}
                                        <br>No files provided
                                        {% endif %}
                                    </li>
                                    {% endfor %}
                                </ul>
                                {% else %}
                                No mitigation defined
                                {% endif %}
                            </td>
                        </tr>
                        {% endfor %}
                    </table>
                </td>
            </tr>
        </table>
        <footer>
            Generated using AWS Mapping v12/12/2024 and MITRE ATT&CK v16.1
        </footer>
    </body>
    </html>
    """)

    # Enhance data with technique names, comments, and references
    enhanced_data = []
    aws_data_path = os.path.join('src', 'env', 'aws-12.12.2024_attack_data-enterprise.json')
    with open(aws_data_path, 'r') as f:
        aws_data = json.load(f)
    technique_map = {m['technique_id']: m for m in aws_data['mapping_data'] if m.get('technique_id')}

    for control in sorted_data:
        enhanced_control = control.copy()
        enhanced_techniques = []
        for tech in control['associated_data']:
            enhanced_tech = tech.copy()
            technique_info = technique_map.get(tech['data_id'], {})
            enhanced_tech['data_name'] = technique_info.get('technique_name')
            enhanced_mitigations = []
            for mitigation in tech['mitigations']:
                enhanced_mitigation = mitigation.copy()
                for mapping in aws_data['mapping_data']:
                    if (mapping.get('technique_id') == tech['data_id'] and 
                        mapping.get('file') == mitigation['file'] and
                        mapping.get('reason') == mitigation['reason'] and
                        mapping.get('level').lower() == mitigation['level'].lower()):
                        enhanced_mitigation['comment'] = mapping.get('comments', '')
                        enhanced_mitigation['files'] = mapping.get('files', [])
                        break
                enhanced_mitigations.append(enhanced_mitigation)
            enhanced_tech['mitigations'] = enhanced_mitigations
            enhanced_techniques.append(enhanced_tech)
        enhanced_control['associated_data'] = enhanced_techniques
        enhanced_data.append(enhanced_control)

    # List to track HTML files for zipping
    html_files = []

    # Generate summary page
    summary_file = os.path.join(output_dir, 'data_summary.html')
    summary_content = summary_template.render(data=enhanced_data, FAMILY_MAPPING=FAMILY_MAPPING, style=common_style)
    with open(summary_file, 'w') as f:
        f.write(summary_content)
    html_files.append(summary_file)

    # Generate per-control detail pages
    for control in enhanced_data:
        detail_file = os.path.join(output_dir, f"data_details_{control['id']}.html")
        detail_content = detail_template.render(control=control, FAMILY_MAPPING=FAMILY_MAPPING, style=common_style)
        with open(detail_file, 'w') as f:
            f.write(detail_content)
        html_files.append(detail_file)

    # Create ZIP file containing all HTML files
    zip_path = os.path.join(output_dir, 'aws_data.zip')
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for html_file in html_files:
            # Use relative path in ZIP to avoid including full directory structure
            arcname = os.path.basename(html_file)
            zipf.write(html_file, arcname)
