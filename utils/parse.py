"""Utility functions to parse risk indicator datasets."""

import json
import pandas as pd
import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def parse_nvd():
    """Parse NVD JSON feeds to extract CVE IDs and CVSS scores.

    Returns:
        list: List of dicts with CVE ID and CVSS score.
    """
    # Paths to the NVD JSON files
    base_path = os.path.join("data", "nvdcve-1.1-2025.json")
    recent_path = os.path.join("data", "nvdcve-1.1-recent.json")
    modified_path = os.path.join("data", "nvdcve-1.1-modified.json")

    # Load JSON files
    cve_dict = {}
    for path in [base_path, recent_path, modified_path]:
        if not os.path.exists(path):
            logging.warning(f"{path} not found, skipping.")
            continue
        try:
            with open(path, "r") as f:
                data = json.load(f)
            # Process NVD 2.0 API structure
            for item in data.get("CVE_Items", []):
                cve = item.get("cve", {})
                cve_id = cve.get("id")
                if not cve_id:
                    logging.warning(f"Skipping item in {path} with missing cve.id")
                    continue
                cve_dict[cve_id] = item
        except json.JSONDecodeError as e:
            logging.warning(f"Failed to parse {path}: {e}")
            continue

    # Extract CVE data from merged CVEs
    merged_cves = list(cve_dict.values())
    result = []
    for item in merged_cves:
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            logging.warning(f"Skipping item with missing cve.id")
            continue
        # Extract CVSS v3.1 score
        score = 0.0
        metrics = cve.get("metrics", {})
        cvss_v31 = metrics.get("cvssMetricV31", [])
        if cvss_v31 and len(cvss_v31) > 0:
            cvss_data = cvss_v31[0].get("cvssData", {})
            score = cvss_data.get("baseScore", 0.0)
        result.append({"cve": cve_id, "score": score})
    logging.info(f"Parsed {len(result)} CVEs from NVD JSON files")
    return result

def parse_kev():
    """Parse CISA KEV CSV to extract exploited CVEs.

    Returns:
        list: List of dicts with CVE IDs and scores.
    """
    csv_path = os.path.join("data", "kev.csv")
    if not os.path.exists(csv_path):
        logging.warning(f"{csv_path} not found, skipping KEV parsing.")
        return []
    try:
        df = pd.read_csv(csv_path)
        if "cveID" not in df.columns:
            logging.warning(f"'cveID' column not found in {csv_path}, skipping KEV parsing.")
            return []
        result = [{"cve": cve, "score": 10.0} for cve in df["cveID"]]
        logging.info(f"Parsed {len(result)} CVEs from CISA KEV CSV")
        return result
    except pd.errors.EmptyDataError:
        logging.warning(f"{csv_path} is empty or invalid, skipping KEV parsing.")
        return []

def parse_attack():
    """Parse MITRE ATT&CK JSON to extract techniques.

    Returns:
        list: List of dicts with technique IDs and scores.
    """
    json_path = os.path.join("data", "attack.json")
    if not os.path.exists(json_path):
        logging.warning(f"{json_path} not found, skipping ATT&CK parsing.")
        return []
    try:
        with open(json_path, "r") as f:
            data = json.load(f)
        result = [
            {"technique": obj["external_references"][0]["external_id"], "score": 5.0}  # Placeholder score
            for obj in data["objects"] if obj["type"] == "attack-pattern"
        ]
        logging.info(f"Parsed {len(result)} techniques from MITRE ATT&CK JSON")
        return result
    except json.JSONDecodeError:
        logging.warning(f"{json_path} is invalid JSON, skipping ATT&CK parsing.")
        return []

def parse_all_datasets():
    """Parse all datasets and return combined risk indicators.

    Returns:
        dict: Dictionary with risk indicators from each source.
    """
    return {
        "nvd": parse_nvd(),
        "kev": parse_kev(),
        "attack": parse_attack()
    }