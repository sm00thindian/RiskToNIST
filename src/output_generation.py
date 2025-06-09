import json
import pandas as pd
import plotly.express as px

def generate_json(control_to_risk, nist_controls, output_file):
    data = [
        {"control_id": control, "description": nist_controls.get(control, "No description"), "total_risk": risk}
        for control, risk in control_to_risk.items()
    ]
    with open(output_file, 'w') as f:
        json.dump(data, f, indent=2)

def generate_csv(control_to_risk, nist_controls, output_file):
    df = pd.DataFrame([
        {"control_id": control, "description": nist_controls.get(control, "No description"), "total_risk": risk}
        for control, risk in control_to_risk.items()
    ])
    df.to_csv(output_file, index=False)

def generate_html(control_to_risk, nist_controls, covered_cves, total_cves, output_file):
    df = pd.DataFrame([
        {"control_id": control, "description": nist_controls.get(control, "No description"), "total_risk": risk}
        for control, risk in control_to_risk.items()
    ]).sort_values(by="total_risk", ascending=False)
    
    bar_fig = px.bar(df.head(10), x="control_id", y="total_risk", title="Top 10 Controls by Risk Mitigated")
    risk_covered = len(covered_cves)
    residual_risk = len(total_cves) - risk_covered
    pie_fig = px.pie(values=[risk_covered, residual_risk], names=["Risk Covered", "Residual Risk"], title="Risk Coverage")
    
    with open(output_file, 'w') as f:
        f.write("<html><body>")
        f.write("<h1>Risktonist Report</h1>")
        f.write("<h2>Prioritized Controls</h2>")
        f.write(df.to_html(index=False))
        f.write("<h2>Top 10 Controls by Risk Mitigated</h2>")
        f.write(bar_fig.to_html(full_html=False))
        f.write("<h2>Risk Coverage</h2>")
        f.write(pie_fig.to_html(full_html=False))
        f.write("</body></html>")
