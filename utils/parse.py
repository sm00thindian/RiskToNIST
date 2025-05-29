import pandas as pd
import os

def parse_csv(csv_path):
    """Parse a single CSV to extract risks, mitigating controls, and scores."""
    try:
        df = pd.read_csv(csv_path)
        risks = []
        for _, row in df.iterrows():
            # Handle missing or empty Mitigating Controls
            mitigating_controls = row.get("Mitigating Controls", "").split(",")
            mitigating_controls = [ctrl.strip().upper() for ctrl in mitigating_controls if ctrl.strip()]
            # Default to 0.0 if scores are missing
            exploitation_score = float(row.get("Exploitation Score", 0.0))
            impact_score = float(row.get("Impact Score", 0.0))
            risks.append({
                "mitigating_controls": mitigating_controls,
                "exploitation_score": exploitation_score,
                "impact_score": impact_score
            })
        return risks
    except Exception as e:
        print(f"Error parsing {csv_path}: {e}")
        return []

def parse_all_datasets(data_dir="data"):
    """Parse all CSV files in the data directory."""
    all_risks = {}
    for filename in os.listdir(data_dir):
        if filename.endswith(".csv"):
            source_name = filename.replace(".csv", "")
            csv_path = os.path.join(data_dir, filename)
            risks = parse_csv(csv_path)
            all_risks[source_name] = risks
    return all_risks