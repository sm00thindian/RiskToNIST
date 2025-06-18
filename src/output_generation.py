import json
import pandas as pd
import plotly.express as px
import logging
import csv
from datetime import datetime
import statistics

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
            cve_list = ', '.join(info['cves'])
            records.append({
                'control_id': control,
                'family': control_info['family'],
                'control_description': control_info['title'],
                'total_risk': info['total_risk'],
                'is_core_control': control.upper() in core_controls,
                'cves': cve_list
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

    # Calculate summary statistics
    total_controls = len(sorted_controls)
    core_control_count = sum(1 for control_id, _ in sorted_controls if control_id.upper() in core_controls)
    risk_scores = [info['total_risk'] for _, info in sorted_controls]
    max_risk = max(risk_scores, default=0)
    median_risk = statistics.median(risk_scores) if risk_scores else 0

    # Define dynamic risk thresholds
    low_threshold = 0.5 * median_risk if median_risk > 0 else 0
    high_threshold = median_risk + 0.5 * (max_risk - median_risk) if max_risk > median_risk else median_risk
    if max_risk == 0:  # Handle edge case
        low_threshold = 0
        high_threshold = 0

    # Start HTML content with enhanced styling
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Cybersecurity Risk Assessment Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; background-color: #f9f9f9; color: #333; }}
            h1 {{ color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
            h2 {{ color: #34495e; margin-top: 30px; }}
            .section {{ background-color: #fff; padding: 20px; margin-bottom: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
            table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
            th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
            th {{ background-color: #3498db; color: white; position: sticky; top: 0; z-index: 10; }}
            tr:nth-child(even) {{ background-color: #f2f2f2; }}
            .collapsible {{ background-color: #34495e; color: white; padding: 10px; cursor: pointer; border: none; border-radius: 3px; display: inline-block; margin: 5px 0; }}
            .collapsible:hover {{ background-color: #2c3e50; }}
            .content {{ display: none; padding: 10px; }}
            .core-yes {{ color: #27ae60; font-weight: bold; }}
            .core-no {{ color: #e74c3c; }}
            .risk-low {{ color: #27ae60; }}
            .risk-medium {{ color: #f39c12; }}
            .risk-high {{ color: #e74c3c; }}
            .risk-bar {{ background-color: #ddd; height: 10px; border-radius: 5px; overflow: hidden; margin: 5px 0; }}
            .risk-bar-fill {{ height: 100%; transition: width 0.3s; }}
            .risk-bar-low {{ background-color: #27ae60; }}
            .risk-bar-medium {{ background-color: #f39c12; }}
            .risk-bar-high {{ background-color: #e74c3c; }}
            .toc {{ position: sticky; top: 0; background-color: #fff; padding: 10px; border-bottom: 1px solid #ddd; z-index: 20; }}
            .toc a {{ margin-right: 15px; color: #3498db; text-decoration: none; }}
            .toc a:hover {{ text-decoration: underline; }}
            .controls {{ margin-bottom: 10px; }}
            .control-btn {{ background-color: #3498db; color: white; padding: 8px 12px; margin-right: 10px; border: none; border-radius: 3px; cursor: pointer; }}
            .control-btn:hover {{ background-color: #2980b9; }}
            @media (max-width: 768px) {{
                table {{ font-size: 14px; }}
                th, td {{ padding: 8px; }}
                .toc {{ font-size: 14px; }}
                .collapsible, .control-btn {{ font-size: 14px; padding: 8px; }}
            }}
            @media (max-width: 480px) {{
                table {{ display: block; overflow-x: auto; }}
                th, td {{ min-width: 100px; }}
            }}
        </style>
    </head>
    <body>
        <nav class="toc" role="navigation" aria-label="Table of Contents">
            <a href="#summary">Summary</a>
            <a href="#about">About</a>
            <a href="#risk-calc">Risk Calculation</a>
            <a href="#controls">Controls</a>
            <a href="#cves">CVE Details</a>
        </nav>

        <h1 id="summary">Cybersecurity Risk Assessment Report</h1>
        <p>Generated by RiskToNIST on {generation_date}</p>
        <p>Total CVEs Analyzed: {total_cves}</p>

        <div class="section">
            <h2>Summary</h2>
            <ul>
                <li><strong>Total Controls Assessed:</strong> {total_controls}</li>
                <li><strong>Core Controls Identified:</strong> {core_control_count}</li>
                <li><strong>Highest Risk Score:</strong> {max_risk:.1f}</li>
                <li><strong>Median Risk Score:</strong> {median_risk:.1f}</li>
            </ul>
        </div>

        <div class="section" id="about">
            <h2>About This Report</h2>
            <p>This report analyzes known vulnerabilities (CVEs) and maps them to NIST SP 800-53 security controls to identify cybersecurity risks in our systems. It prioritizes controls by risk level, with higher scores indicating urgent attention. Controls marked as 'Core' are critical, as defined in <code>core_controls.csv</code>. Use the navigation above to explore sections or click 'View CVEs' to see detailed vulnerability information.</p>
        </div>

        <div class="section" id="risk-calc">
            <h2>How We Calculate Risk</h2>
            <p>Each NIST control’s risk score is the sum of risk contributions from its associated vulnerabilities (CVEs). CVE risk is determined by severity, exploitability, and impact, per our data mappings. Risk scores are color-coded based on the dataset: <span class="risk-low">Low (&lt;{low_threshold:.1f})</span>, <span class="risk-medium">Medium ({low_threshold:.1f}-{high_threshold:.1f})</span>, <span class="risk-high">High (&gt;{high_threshold:.1f})</span>.</p>
        </div>

        <div class="section" id="controls">
            <h2>Risk-Based Control Assessment</h2>
            <div class="controls">
                <button class="control-btn" onclick="toggleAll(true)">Expand All CVEs</button>
                <button class="control-btn" onclick="toggleAll(false)">Collapse All CVEs</button>
            </div>
            <table role="grid">
                <tr>
                    <th scope="col">Control ID</th>
                    <th scope="col">Family</th>
                    <th scope="col">Control Description</th>
                    <th scope="col">Total Risk</th>
                    <th scope="col">Is Core Control</th>
                    <th scope="col">Associated CVEs</th>
                </tr>
    """.format(
        generation_date=datetime.now().strftime("%B %d, %Y at %I:%M %p CDT"),  # June 18, 2025 at 02:31 PM CDT
        total_cves=total_cves,
        total_controls=total_controls,
        core_control_count=core_control_count,
        max_risk=max_risk,
        median_risk=median_risk,
        low_threshold=low_threshold,
        high_threshold=high_threshold
    )

    # Add table rows for each control
    for control_id, info in sorted_controls:
        control_info = nist_controls.get(control_id.upper(), {'family': 'Unknown', 'title': 'No description available'})
        family = control_info.get('family', 'Unknown')
        description = control_info.get('title', 'No description available')
        total_risk = info['total_risk']
        cve_count = len(info['cves'])
        is_core = 'Yes' if control_id.upper() in core_controls else 'No'
        core_class = 'core-yes' if is_core == 'Yes' else 'core-no'
        risk_class = 'risk-low' if total_risk <= low_threshold else 'risk-medium' if total_risk <= high_threshold else 'risk-high'
        risk_bar_class = 'risk-bar-low' if total_risk <= low_threshold else 'risk-bar-medium' if total_risk <= high_threshold else 'risk-bar-high'
        risk_percentage = min(total_risk / max_risk * 100, 100) if max_risk > 0 else 0

        html_content += f"""
                <tr>
                    <td>{control_id.upper()}</td>
                    <td>{family}</td>
                    <td>{description}</td>
                    <td class="{risk_class}">{total_risk:.1f}
                        <div class="risk-bar"><div class="risk-bar-fill {risk_bar_class}" style="width: {risk_percentage}%"></div></div>
                    </td>
                    <td class="{core_class}">{is_core}</td>
                    <td>
                        <button class="collapsible" onclick="toggleCVE('{control_id}')" onkeypress="if(event.key === 'Enter') toggleCVE('{control_id}')" aria-expanded="false" aria-controls="cve_{control_id}" tabindex="0">View {cve_count} CVE{'s' if cve_count != 1 else ''}</button>
                    </td>
                </tr>
        """

    html_content += """
            </table>
            <p><em>Note: Controls are sorted by total risk (highest first). Click 'View CVEs' to see vulnerabilities or use the buttons above to expand/collapse all.</em></p>
        </div>

        <div class="section" id="cves">
            <h2>Detailed CVE Information</h2>
    """

    # Add detailed CVE sections for each control
    for control_id, info in sorted_controls:
        if not info['cves']:
            continue
        html_content += f"""
            <div id="cve_{control_id}" class="content" role="region" aria-labelledby="cve_{control_id}_header">
                <h3 id="cve_{control_id}_header">CVEs for Control {control_id.upper()}</h3>
                <table>
                    <tr>
                        <th scope="col">CVE ID</th>
                        <th scope="col">Vulnerability Name</th>
                        <th scope="col">Description</th>
                        <th scope="col">Due Date</th>
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
                        <td><a href="https://nvd.nist.gov/vuln/detail/{cve}" target="_blank" rel="noopener">{cve}</a></td>
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
            function toggleCVE(controlId) {{
                var content = document.getElementById('cve_' + controlId);
                var button = document.querySelector('button[aria-controls="cve_' + controlId + '"]');
                var isExpanded = content.style.display === 'block';
                content.style.display = isExpanded ? 'none' : 'block';
                button.setAttribute('aria-expanded', !isExpanded);
            }}
            function toggleAll(expand) {{
                var contents = document.querySelectorAll('.content');
                var buttons = document.querySelectorAll('.collapsible');
                contents.forEach(function(content) {{
                    content.style.display = expand ? 'block' : 'none';
                }});
                buttons.forEach(function(button) {{
                    button.setAttribute('aria-expanded', expand);
                }});
            }}
        </script>
    </body>
    </html>
    """.format(year=datetime.now().year)

    with open(output_file, 'w') as f:
        f.write(html_content)