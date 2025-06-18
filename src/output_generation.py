import json
import pandas as pd
import plotly.express as px
import logging
import csv
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def load_core_controls(file_path):
    core_controls = set()
    try:
        with open(file_path, 'r') as f:
            reader = csv.reader(f)
            for row in reader:
                for control in row:
                    if control:  # Only add non-empty values
                        core_controls.add(control.upper())
    except FileNotFoundError:
        logger.warning(f"Core controls file {file_path} not found, all controls will be treated as non-core")
    except Exception as e:
        logger.error(f"Error reading core controls file {file_path}: {e}")
    return core_controls

def generate_json(control_to_risk, nist_controls, cve_details, output_file, core_controls_file='core_controls.csv'):
    core_controls = load_core_controls(core_controls_file)
    
    if not control_to_risk:
        logger.warning("No controls mapped to CVEs. JSON output will be empty.")
    
    data = []
    for control, info in control_to_risk.items():
        try:
            cve_list = [
                {
                    'cveID': cve,
                    'vulnerabilityName': cve_details[cve]['name'],
                    'shortDescription': cve_details[cve]['description'],
                    'dueDate': cve_details[cve]['dueDate']
                } for cve in info['cves']
            ]
            control_info = nist_controls.get(control.upper(), {'family': 'Unknown', 'title': 'Unknown'})
            data.append({
                'control_id': control,
                'family': control_info['family'],
                'description': control_info['title'],
                'total_risk': info['total_risk'],
                'is_core_control': control.upper() in core_controls,
                'cves': cve_list
            })
        except KeyError as e:
            logger.warning(f"Skipping control {control} due to missing data: {e}")
            continue
    
    data.sort(key=lambda x: x['total_risk'], reverse=True)
    with open(output_file, 'w') as f:
        json.dump(data, f, indent=2)

def generate_csv(control_to_risk, nist_controls, cve_details, output_file, core_controls_file='core_controls.csv'):
    core_controls = load_core_controls(core_controls_file)
    
    if not control_to_risk:
        logger.warning("No controls mapped to CVEs. CSV output will be empty.")
        pd.DataFrame().to_csv(output_file, index=False)
        return
    
    records = []
    for control, info in control_to_risk.items():
        if 'total_risk' not in info or 'cves' not in info:
            logger.error(f"Invalid control_to_risk entry for {control}: {info}")
            continue
        try:
            control_info = nist_controls.get(control.upper(), {'family': 'Unknown', 'title': 'Unknown'})
            for cve in info['cves']:
                records.append({
                    'control_id': control,
                    'family': control_info['family'],
                    'control_description': control_info['title'],
                    'total_risk': info['total_risk'],
                    'is_core_control': control.upper() in core_controls,
                    'cveID': cve,
                    'vulnerabilityName': cve_details[cve]['name'],
                    'shortDescription': cve_details[cve]['description'],
                    'dueDate': cve_details[cve]['dueDate']
                })
        except KeyError as e:
            logger.warning(f"Skipping control {control} due to missing data: {e}")
            continue
    
    if not records:
        logger.warning("No valid records generated for CSV output.")
        pd.DataFrame().to_csv(output_file, index=False)
        return
    
    df = pd.DataFrame(records)
    try:
        df = df.sort_values(by="total_risk", ascending=False)
        df.to_csv(output_file, index=False)
    except KeyError as e:
        logger.error(f"Failed to sort CSV DataFrame: {e}")
        df.to_csv(output_file, index=False)

def generate_html(control_to_risk, nist_controls, cve_details, total_cves, output_file, core_controls_file='core_controls.csv'):
    core_controls = load_core_controls(core_controls_file)
    
    # Sort controls by total_risk in descending order
    sorted_controls = sorted(
        control_to_risk.items(),
        key=lambda x: x[1]['total_risk'],
        reverse=True
    )

    # Start HTML content with improved styling
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Cybersecurity Risk Assessment Report</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                line-height: 1.6;
                margin: 20px;
                background-color: #f9f9f9;
                color: #333;
            }
            h1 {
                color: #2c3e50;
                border-bottom: 2px solid #3498db;
                padding-bottom: 10px;
            }
            h2 {
                color: #34495e;
                margin-top: 20px;
            }
            .section {
                background-color: #fff;
                padding: 15px;
                margin-bottom: 20px;
                border-radius: 5px;
                box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            }
            table {
                width: 100%;
                border-collapse: collapse;
                margin: 20px 0;
            }
            th, td {
                border: 1px solid #ddd;
                padding: 10px;
                text-align: left;
            }
            th {
                background-color: #3498db;
                color: white;
            }
            tr:nth-child(even) {
                background-color: #f2f2f2;
            }
            .collapsible {
                background-color: #34495e;
                color: white;
                padding: 10px;
                cursor: pointer;
                border: none;
                width: 100%;
                text-align: left;
                outline: none;
                margin-bottom: 5px;
            }
            .content {
                display: none;
                padding: 10px;
            }
            .core-yes {
                color: #27ae60;
                font-weight: bold;
            }
            .core-no {
                color: #e74c3c;
            }
        </style>
    </head>
    <body>
        <h1>Cybersecurity Risk Assessment Report</h1>
        <p>Generated by RiskToNIST on {generation_date}</p>
        <p>Total CVEs Analyzed: {total_cves}</p>

        <div class="section">
            <h2>About This Report</h2>
            <p>This report provides a clear overview of cybersecurity risks within our systems by analyzing known vulnerabilities (CVEs) and linking them to NIST SP 800-53 security controls. It helps us identify the controls most at risk, enabling us to prioritize actions to enhance our security posture. Controls are ranked by risk level, with the highest-risk items listed first. Additionally, controls marked as 'Core' are part of our critical control set, as defined in <code>core_controls.csv</code>.</p>
        </div>

        <div class="section">
            <h2>How We Calculate Risk</h2>
            <p>The risk score for each NIST control is determined by summing the risk contributions from all associated vulnerabilities (CVEs). Each CVE's risk is based on its severity, exploitability, and potential impact, as outlined in our data mappings. Higher scores indicate controls that require urgent attention due to significant or numerous vulnerabilities.</p>
        </div>

        <div class="section">
            <h2>Risk-Based Control Assessment</h2>
            <table>
                <tr>
                    <th>Control ID</th>
                    <th>Family</th>
                    <th>Control Description</th>
                    <th>Total Risk</th>
                    <th>Is Core Control</th>
                    <th>Associated CVEs</th>
                </tr>
    """

    html_content += """
            </table>
            <p><em>Note: Controls are sorted by total risk, with the highest-risk items at the top. Click the 'View CVEs' link to see detailed vulnerability information for each control.</em></p>
        </div>

        <div class="section">
            <h2>Detailed CVE Information</h2>
    """

    # Add table rows for each control with improved formatting
    for control_id, info in sorted_controls:
        control_info = nist_controls.get(control_id.upper(), {'family': 'Unknown', 'title': 'No description available'})
        family = control_info.get('family', 'Unknown')
        description = control_info.get('title', 'No description available')
        total_risk = info['total_risk']
        cve_count = len(info['cves'])
        is_core = 'Yes' if control_id.upper() in core_controls else 'No'
        core_class = 'core-yes' if is_core == 'Yes' else 'core-no'

        html_content += f"""
            <tr>
                <td>{control_id.upper()}</td>
                <td>{family}</td>
                <td>{description}</td>
                <td>{total_risk:.1f}</td>
                <td class="{core_class}">{is_core}</td>
                <td><span onclick="toggleCVE('{control_id}')" class="collapsible">View {cve_count} CVE{'s' if cve_count != 1 else ''}</span></td>
            </tr>
        """

    # Add detailed CVE sections for each control
    for control_id, info in sorted_controls:
        if not info['cves']:
            continue
        html_content += f"""
            <div id="cve_{control_id}" class="content">
                <h3>CVEs for Control {control_id.upper()}</h3>
                <table>
                    <tr>
                        <th>CVE ID</th>
                        <th>Vulnerability Name</th>
                        <th>Description</th>
                        <th>Due Date</th>
                    </tr>
        """

        sorted_cves = sorted(
            info['cves'],
            key=lambda cve: (
                datetime.strptime(cve_details[cve]['dueDate'], '%Y-%m-%d')
                if cve_details[cve]['dueDate'] != 'N/A'
                else datetime.min
            ),
            reverse=True
        )
        for cve in sorted_cves:
            cve_info = cve_details.get(cve, {'name': 'Unknown', 'description': 'No description available', 'dueDate': 'N/A'})
            html_content += f"""
                    <tr>
                        <td>{cve}</td>
                        <td>{cve_info['name']}</td>
                        <td>{cve_info['description']}</td>
                        <td>{cve_info['dueDate']}</td>
                    </tr>
            """

        html_content += """
                </table>
            </div>
        """

    html_content += """
        </div>

        <div class="section">
            <p>Generated by RiskToNIST | © {year} All rights reserved.</p>
        </div>

        <script>
            function toggleCVE(controlId) {
                var content = document.getElementById('cve_' + controlId);
                if (content.style.display === 'block') {
                    content.style.display = 'none';
                } else {
                    content.style.display = 'block';
                }
            }
        </script>
    </body>
    </html>
    """.format(
        generation_date=datetime.now().strftime("%B %d, %Y at %I:%M %p CDT"),
        total_cves=total_cves,
        year=datetime.now().year
    )

    with open(output_file, 'w') as f:
        f.write(html_content)