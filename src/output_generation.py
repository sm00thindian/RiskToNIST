import json
import pandas as pd
import plotly.express as px

def generate_json(control_to_risk, nist_controls, output_file):
    data = [
        {"control_id": control, "family": nist_controls[control]['family'], "description": nist_controls[control]['title'], "total_risk": risk}
        for control, risk in control_to_risk.items()
    ]
    data.sort(key=lambda x: x['total_risk'], reverse=True)
    with open(output_file, 'w') as f:
        json.dump(data, f, indent=2)

def generate_csv(control_to_risk, nist_controls, output_file):
    df = pd.DataFrame([
        {"control_id": control, "family": nist_controls[control]['family'], "description": nist_controls[control]['title'], "total_risk": risk}
        for control, risk in control_to_risk.items()
    ]).sort_values(by="total_risk", ascending=False)
    df.to_csv(output_file, index=False)

def generate_html(control_to_risk, nist_controls, total_cves, output_file):
    data = [
        {"control_id": control, "family": nist_controls[control]['family'], "description": nist_controls[control]['title'], "total_risk": risk}
        for control, risk in control_to_risk.items()
    ]
    df = pd.DataFrame(data).sort_values(by="total_risk", ascending=False)
    
    # Bar chart for top 10 controls
    bar_fig = px.bar(df.head(10), x="control_id", y="total_risk", title="Top 10 Controls by KEVs Mitigated",
                     labels={"total_risk": "Number of KEVs Mitigated", "control_id": "Control ID"})
    
    # Family pie chart
    family_risk = df.groupby("family")["total_risk"].sum().reset_index()
    pie_fig = px.pie(family_risk, values="total_risk", names="family", title="KEVs Mitigated by Control Family")
    
    # Summary statistics
    total_mitigated = sum(control_to_risk.values())
    
    # Write HTML
    with open(output_file, 'w') as f:
        f.write("""
        <html>
        <head>
            <title>Risktonist Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                table { border-collapse:
