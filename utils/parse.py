import pandas as pd
import json
import os

def parse_csv(csv_path):
    """Parse a single CSV to extract risks, mitigating controls, and scores.

    Args:
        csv_path (str): Path to the CSV file.

    Returns:
        list: List of dictionaries with risk data.
    """
    try:
        df = pd.read_csv(csv_path)
        risks = []
        for _, row in df.iterrows():
            mitigating_controls = row.get("Mitigating Controls", "").split(",")
            mitigating_controls = [ctrl.strip().upper() for ctrl in mitigating_controls if ctrl.strip()]
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

def parse_nvd(data_dir):
    """Parse NVD JSON files to extract CVE IDs and CVSS scores.

    Args:
        data_dir (str): Directory containing NVD JSON files.

    Returns:
        list: List of dictionaries with CVE data.
    """
    paths = [
        os.path.join(data_dir, "nvdcve-1.1-2025.json"),
        os.path.join(data_dir, "nvdcve-1.1-recent.json"),
        os.path.join(data_dir, "nvdcve-1.1-modified.json")
    ]
    cve_dict = {}
    for path in paths:
        if not os.path.exists(path):
            print(f"{path} not found, skipping.")
            continue
        try:
            with open(path, "r") as f:
                data = json.load(f)
            for item in data.get("CVE_Items", []):
                cve = item.get("cve", {})
                cve_id = cve.get("id")
                if cve_id:
                    cve_dict[cve_id] = item
        except json.JSONDecodeError as e:
            print(f"Failed to parse {path}: {e}")
            continue
    
    risks = []
    for item in cve_dict.values():
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            continue
        score = 0.0
        metrics = cve.get("metrics", {})
        cvss_v31 = metrics.get("cvssMetricV31", [])
        if cvss_v31 and len(cvss_v31) > 0:
            score = cvss_v31[0].get("cvssData", {}).get("baseScore", 0.0)
        risks.append({
            "mitigating_controls": ["RA-5"],  # Default mapping for vulnerabilities
            "exploitation_score": score,
            "impact_score": score  # Use CVSS score for both
        })
    print(f"Parsed {len(risks)} CVEs from NVD JSON files")
    return risks

def parse_all_datasets(data_dir="data"):
    """Parse all datasets (CSV and NVD JSON) in the data directory.

    Args:
        data_dir (str): Directory containing data files.

    Returns:
        dict: Dictionary mapping source names to lists of risks.
    """
    all_risks = {}
    for filename in os.listdir(data_dir):
        if filename.endswith(".csv"):
            source_name = filename.replace(".csv", "")
            csv_path = os.path.join(data_dir, filename)
            all_risks[source_name] = parse_csv(csv_path)
    
    # Parse NVD data if present
    if any(os.path.exists(os.path.join(data_dir, f)) for f in ["nvdcve-1.1-2025.json", "nvdcve-1.1-recent.json", "nvdcve-1.1-modified.json"]):
        all_risks["nvd_cve"] = parse_nvd(data_dir)
    
    return all_risks