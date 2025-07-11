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
    """Export prioritized controls to a CSV file, sorted by risk level, mitigation coverage, technique count, and control ID.

    Args:
        data (list): List of control dictionaries.
        file_path (str): Path to save the CSV file.
    """
    # Sort data to match HTML output
    sorted_data = sorted(data, key=lambda x: (-x['risk_level'], -x['mitigation_coverage'], -x['technique_count'], x['id']))
    with open(file_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Control ID', 'Control Name', 'Family Name', 'Risk Level', 'Mitigation Coverage'])
        for control in sorted_data:
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
            This report enables organizations to prioritize NIST 800-53 control selection for AWS workloads by focusing on risk exposure derived from MITRE ATT&CK techniques and AWS service mitigations. 
            For organizations driving risk-prioritized control selection, use this data to align security investments with your risk tolerance and threat profile. Start with high-risk controls (Risk Level 3 and 2), assess mitigation coverage to identify controls with robust AWS protections, and review unmitigated techniques in detail pages to address gaps through additional controls or compensating measures. 
            Cross-reference with your AWS workload inventory to ensure relevance to your environment.
        </p>
        <p>
            For Authorizing Officials (AOs), this report supports risk-based authorization decisions under NIST SP 800-37. High-risk controls (Risk Level 3 and 2) indicate critical vulnerabilities requiring immediate attention to meet compliance and security objectives. Risk Level 1 controls suggest moderate risk with limited mitigations, warranting further evaluation. Use the mitigation coverage metric to evaluate control effectiveness and identify gaps where unmitigated techniques (Risk Level 0) may necessitate enhanced monitoring or alternative mitigations. Incorporate this data into your System Security Plan (SSP) to document control implementation and residual risk, ensuring informed authorization decisions.
        </p>
        <p>
            <strong>Risk Level</strong> (0–3) indicates the criticality of implementing each control:
            <ul>
                <li><strong>0</strong>: No mitigation for at least one associated technique, indicating high risk. Prioritize these controls for additional mitigations or compensating controls to address unmitigated vulnerabilities.</li>
                <li><strong>1</strong>: Minimal mitigation, indicating moderate risk. These controls have limited AWS protections and require further evaluation to determine if additional mitigations, monitoring, or risk acceptance are appropriate.</li>
                <li><strong>2</strong>: Partial mitigation, indicating high risk with significant exposure. Implement these controls promptly, focusing on enhancing AWS mitigations or supplementing with other security measures.</li>
                <li><strong>3</strong>: Significant mitigation, indicating critical risk effectively mitigated by AWS services. These controls are high-priority but well-protected, requiring validation of implementation.</li>
            </ul>
            Risk levels are determined by the minimum mitigation level of associated ATT&CK techniques, weighted by the effectiveness of AWS services (significant, partial, minimal, or none). 
            Within the same risk level, controls are prioritized by mitigation coverage (proportion of mitigated techniques) and number of associated techniques. 
            Click "Details" to view detailed mitigation information for each control. 
            All HTML reports are also available as a single ZIP file: <a href="aws_controls.zip">aws_controls.zip</a>.
        </p>

        <h2>Control Summary</h2>
        <table>
            <tr>
                <th>Control ID</th>
                <th>Control Name</th>
                <th>Family</th>
                <th>Risk Level</th>
                <th>Mitigation Coverage</th>
                <th>Details</th>
            </tr>
            {% for control in data %}
            <tr>
                <td>{{ control.id }}</td>
                <td>{{ control.name }}</td>
                <td>{{ FAMILY_MAPPING.get(control.family, control.family) }}</td>
                <td>{{ control.risk_level }}</td>
                <td>{{ (control.mitigation_coverage*100)|round(1) }}% ({{ control.associated_techniques|selectattr('mitigations')|list|length }}/{{ control.technique_count }})</td>
                <td><a href="aws_controls_details_{{ control.id }}.html">View Details</a></td>
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
        <h1>Prioritized NIST 	int	{{ control.id }} - {{ control.name }}</h1>
        <p>
            This page provides detailed information for NIST 800-53 control {{ control.id }}, including its family, risk level, mitigation coverage, and associated MITRE ATT&CK techniques with AWS mitigations. 
            Return to the <a href="aws_controls_summary.html">Summary page</a> to view all controls. 
            Techniques with "No AWS mitigations defined" indicate no specific AWS service mappings in the input data, suggesting higher risk due to unmitigated vulnerabilities. 
            Assess these techniques further based on your environment’s exposure and the technique’s severity. 
            Click on mitigation comments for additional details.
            All HTML reports are also available as a single ZIP file: <a href="aws_controls.zip">aws_controls.zip</a>.
        </p>
        <table>
            <tr>
                <th>Control ID</th>
                <th>Control Name</th>
                <th>Family</th>
                <th>Risk Level</th>
                <th>Mitigation Coverage</th>
                <th>Associated ATT&CK Techniques</th>
            </tr>
            <tr id="{{ control.id }}">
                <td>{{ control.id }}</td>
                <td>{{ control.name }}</td>
                <td>{{ FAMILY_MAPPING.get(control.family, control.family) }}</td>
                <td>{{ control.risk_level }}</td>
                <td>{{ (control.mitigation_coverage*100)|round(1) }}% ({{ control.associated_techniques|selectattr('mitigations')|list|length }}/{{ control.technique_count }})</td>
                <td>
                    <table class="nested-table">
                        {% for tech in control.associated_techniques %}
                        <tr>
                            <td>{{ tech.technique_id }}: {{ tech.technique_name | default('Unknown Technique') }}</td>
                            <td>
                                {% if tech.mitigations %}
                                <ul>
                                    {% for mitigation in tech.mitigations %}
                                    <li>
                                        {{ mitigation.aws_service }} ({{ mitigation.score_category }}, {{ mitigation.score_value }})
                                        {% if mitigation.comment %}
                                        <span class="comment" title="{{ mitigation.comment | e }}">{{ mitigation.comment[:100] | e }}{% if mitigation.comment|length > 100 %}...{% endif %}
                                            <span class="tooltip">{{ mitigation.comment | e }}</span>
                                        </span>
                                        {% endif %}
                                        {% if mitigation.references %}
                                        <br>References:
                                        <ul>
                                            {% for ref in mitigation.references %}
                                            <li><a href="{{ ref | e }}" target="_blank">{{ ref | truncate(50) | e }}</a></li>
                                            {% endfor %}
                                        </ul>
                                        {% else %}
                                        <br>No references provided
                                        {% endif %}
                                    </li>
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
        </table>
        <footer>
            Generated using AWS Mapping v12/12/2024 and MITRE ATT&CK v16.1
        </footer>
    </body>
    </html>
    """)

    # Enhance data with technique names, comments, and references
    enhanced_data = []
    aws_data_path = os.path.join('src', 'env', 'aws-12.12.2024_attack-16.1-enterprise.json')
    with open(aws_data_path, 'r') as f:
        aws_data = json.load(f)
    technique_map = {m['attack_object_id']: m for m in aws_data['mapping_objects'] if m.get('attack_object_id')}

    for control in sorted_data:
        enhanced_control = control.copy()
        enhanced_techniques = []
        for tech in control['associated_techniques']:
            enhanced_tech = tech.copy()
            technique_info = technique_map.get(tech['technique_id'], {})
            enhanced_tech['technique_name'] = technique_info.get('attack_object_name')
            enhanced_mitigations = []
            for mitigation in tech['mitigations']:
                enhanced_mitigation = mitigation.copy()
                for mapping in aws_data['mapping_objects']:
                    if (mapping.get('attack_object_id') == tech['technique_id'] and
                        mapping.get('capability_description') == mitigation['aws_service'] and
                        mapping.get('score_category') == mitigation['score_category'] and
                        mapping.get('score_value').lower() == mitigation['score_value'].lower()):
                        enhanced_mitigation['comment'] = mapping.get('comments', '')
                        enhanced_mitigation['references'] = mapping.get('references', [])
                        break
                enhanced_mitigations.append(enhanced_mitigation)
            enhanced_tech['mitigations'] = enhanced_mitigations
            enhanced_techniques.append(enhanced_tech)
        enhanced_control['associated_techniques'] = enhanced_techniques
        enhanced_data.append(enhanced_control)

    # List to track HTML files for zipping
    html_files = []

    # Generate summary page
    summary_file = os.path.join(output_dir, 'aws_controls_summary.html')
    summary_content = summary_template.render(data=enhanced_data, FAMILY_MAPPING=FAMILY_MAPPING, style=common_style)
    with open(summary_file, 'w') as f:
        f.write(summary_content)
    html_files.append(summary_file)

    # Generate per-control detail pages
    for control in enhanced_data:
        detail_file = os.path.join(output_dir, f"aws_controls_details_{control['id']}.html")
        detail_content = detail_template.render(control=control, FAMILY_MAPPING=FAMILY_MAPPING, style=common_style)
        with open(detail_file, 'w') as f:
            f.write(detail_content)
        html_files.append(detail_file)

    # Create ZIP file containing all HTML files
    zip_path = os.path.join(output_dir, 'aws_controls.zip')
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for html_file in html_files:
            # Use relative path in ZIP to avoid including full directory structure
            arcname = os.path.basename(html_file)
            zipf.write(html_file, arcname)
