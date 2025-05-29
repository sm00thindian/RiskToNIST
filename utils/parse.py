import pandas as pd
import json
import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

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
        source_name = os.path.basename(csv_path).replace(".csv", "")
        for _, row in df.iterrows():
            # Handle CISA KEV specifically
            if source_name == "cisa_kev":
                cve_id = row.get("cveID", "")
                if not cve_id:
                    logging.warning(f"Skipping row in {csv_path} with missing cveID")
                    continue
                risks.append({
                    "mitigating_controls": ["SI-2"],  # Flaw Remediation for exploited CVEs
                    "exploitation_score": 10.0,  # High score for known exploited vulnerabilities
                    "impact_score": 10.0
                })
            else:
                mitigating_controls = row.get("Mitigating Controls", "").split(",")
                mitigating_controls = [ctrl.strip().upper() for ctrl in mitigating_controls if ctrl.strip()]
                exploitation_score = float(row.get("Exploitation Score", 0.0))
                impact_score = float(row.get("Impact Score", 0.0))
                risks.append({
                    "mitigating_controls": mitigating_controls,
                    "exploitation_score": exploitation_score,
                    "impact_score": impact_score
                })
        logging.info(f"Parsed {len(risks)} risks from {csv_path}")
        return risks
    except Exception as e:
        logging.error(f"Error parsing {csv_path}: {e}")
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
            logging.warning(f"{path} not found, skipping.")
            continue
        try:
            with open(path, "r") as f:
                data = json.load(f)
            cve_items = data.get("CVE_Items", [])
            logging.info(f"Found {len(cve_items)} items in {path}")
            for item in cve_items:
                cve = item.get("cve", {})
                cve_id = cve.get("id")
                if cve_id:
                    cve_dict[cve_id] = item
                else:
                    logging.warning(f"Skipping item in {path} with missing cve.id")
        except json.JSONDecodeError as e:
            logging.error(f"Failed to parse {path}: {e}")
            continue
    
    risks = []
    for item in cve_dict.values():
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            logging.warning("Skipping item with missing cve.id")
            continue
        score = 0.0
        metrics = cve.get("metrics", {})
        cvss_v31 = metrics.get("cvssMetricV31", [])
        if cvss_v31 and len(cvss_v31) > 0:
            cvss_data = cvss_v31[0].get("cvssData", {})
            score = cvss_data.get("baseScore", 0.0)
            logging.debug(f"CVE {cve_id}: CVSS score {score}")
        else:
            logging.debug(f"CVE {cve_id}: No CVSS v3.1 score, defaulting to 0.0")
        risks.append({
            "mitigating_controls": ["RA-5"],  # Vulnerability Scanning
            "exploitation_score": score,
            "impact_score": score
        })
    logging.info(f"Parsed {len(risks)} CVEs from NVD JSON files")
    return risks

def parse_all_datasets(data_dir="data"):
    """Parse all datasets (CSV and NVD JSON) in the data directory.

    Args:
        data_dir (str): Directory containing data files.

    Returns:
        dict: Dictionary mapping source names to lists of risks.
    """
    all_risks = {}
    csv_count = 0
    for filename in os.listdir(data_dir):
        if filename.endswith(".csv"):
            source_name = filename.replace(".csv", "")
            csv_path = os.path.join(data_dir, filename)
            risks = parse_csv(csv_path)
            if risks:
                all_risks[source_name] = risks
                csv_count += 1
    
    # Parse NVD data if present
    if any(os.path.exists(os.path.join(data_dir, f)) for f in ["nvdcve-1.1-2025.json", "nvdcve-1.1-recent.json", "nvdcve-1.1-modified.json"]):
        nvd_risks = parse_nvd(data_dir)
        if nvd_risks:
            all_risks["nvd_cve"] = nvd_risks
    
    # Fallback data if no risks parsed
    if not all_risks:
        logging.warning("No valid risk data parsed, using fallback data")
        all_risks["fallback"] = [
            {"mitigating_controls": ["SI-2"], "exploitation_score": 8.0, "impact_score": 8.0},  # Vulnerability remediation
            {"mitigating_controls": ["IA-5"], "exploitation_score": 7.0, "impact_score": 7.0},  # Credential abuse
            {"mitigating_controls": ["AT-2"], "exploitation_score": 6.0, "impact_score": 6.0}   # Phishing training
        ]
        logging.info("Added fallback risks for SI-2, IA-5, AT-2")
    
    logging.info(f"Parsed risks from {csv_count} CSVs and NVD data: {sum(len(risks) for risks in all_risks.values())} total risks")
    return all_risks