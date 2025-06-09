import json
import pandas as pd
import plotly.express as px

def generate_json(control_to_risk, nist_controls, cve_details, output_file):
    data = []
    for control, info in control_to_risk.items():
        cve_list = [
            {
                'cveID': cve,
                'vulnerabilityName': cve_details[cve]['name'],
                'shortDescription': cve_details[cve]['description'],
                'dueDate': cve_details[cve]['dueDate']
            } for cve in info['cves']
        ]
        data.append({
            'control_id': control,
            'family': nist_controls[control]['family'],
            'description': nist_controls[control]['title'],
            'total_risk': info['total_risk'],
            'cves': cve_list
        })
    data.sort(key=lambda x: x['total_risk'], reverse=True)
    with open(output_file, 'w') as f:
        json.dump(data, f, indent=2)

def generate_csv(control_to_risk, nist_controls, cve_details, output_file):
    records = []
    for control, info in control_to_risk.items():
        for cve in info['cves']:
            records.append({
                'control_id': control,
                'family': nist_controls[control]['family'],
                'control_description': nist_controls[control]['title'],
                'total_risk': info['total_risk'],
                'cveID': cve,
                'vulnerabilityName': cve_details[cve]['name'],
                'shortDescription': cve_details[cve]['description'],
                'dueDate': cve_details[cve]['dueDate']
            })
    df = pd.DataFrame(records).sort_values(by="total_risk", ascending=False)
    df.to_csv(output_file, index=False)

def generate_html(control_to_risk, nist_controls, cve_details, total_cves, output_file):
    data = []
    for control, info in control_to_risk.items():
        data.append({
            'control_id': control,
            'family': nist_controls[control]['family'],
            'description': nist_controls[control]['title'],
            'total_risk': info['total_risk']
        })
    control_df = pd.DataFrame(data).sort_values(by="total_risk", ascending=False)
    
    cve_data = []
    for control, info in control_to_risk.items():
        for cve in info['cves']:
            cve_data.append({
                'control_id': control,
                'cveID': cve,
                'vulnerabilityName': cve_details[cve]['name'],
                'shortDescription': cve_details[cve]['description'],
                'dueDate': cve_details[cve]['dueDate']
            })
    cve_df = pd.DataFrame(cve_data)
    
    # Bar chart for top 10 controls
    bar_fig = px.bar(control_df.head(10), x="control_id", y="total_risk", title="Top 10 Controls by Risk Mitigated",
                     labels={"total_risk": "Risk Score", "control_id": "Control ID"})
    
    # Family pie chart
    family_risk = control_df.groupby("family")["total_risk"].sum().reset_index()
    pie_fig = px.pie(family_risk, values="total_risk", names="family", title="Risk Mitigated by Control Family")
    
    # Summary statistics
    total_mitigated = sum(info['total_risk'] for info in control_to_risk.values())
    
    # Write HTML
    with open(output_file, 'w') as f:
        f.write("""
        <html>
        <head>
            <title>Risktonist Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
                h2 { margin-top: 30px; }
            </style>
        </head>
        <body>
            <h1>Risktonist Report</h1>
            <h2>Summary</h2>
            <p>Total number of KEVs: {}</p>
            <p>Total risk mitigated by recommended controls: {:.2f}</p>
            <p>Number of controls mitigating at least one KEV: {}</p>
            <h2>Prioritized Controls</h2>
            {}
            <h2>Top 10 Controls by Risk Mitigated</h2>
            {}
            <h2>Risk Mitigated by Control Family</h2>
            {}
            <h2>Associated Vulnerabilities</h2>
            {}
        </body>
        </html>
        """.format(total_cves, total_mitigated, len(control_to_risk), control_df.to_html(index=False),
                   bar_fig.to_html(full_html=False), pie_fig.to_html(full_html=False), cve_df.to_html(index=False)))
