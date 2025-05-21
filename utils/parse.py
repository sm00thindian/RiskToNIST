"""Utility functions to parse risk indicator datasets."""

import json
import pandas as pd
import os
from utils.schema import download_schema, validate_json

def parse_nvd():
    """Parse NVD JSON feeds to extract CVE IDs and CVSS scores.

    Returns:
        list: List of dicts with CVE ID and CVSS score.
    """
    schema_url = "https://csrc.nist.gov/schema/nvd/feed/1.1/nvd_cve_feed_json_1.1.schema"
    schema_path = os.path.join("mappings", "nvd_schema.json")
    download_schema(schema_url, schema_path)

    # Paths to the NVD JSON files
    base_path = os.path.join("data", "nvdcve-1.1-2025.json")
    recent_path = os.path.join("data", "nvdcve-1.1-recent.json")
    modified_path = os.path.join("data", "nvdcve-1.1-modified.json")

    # Load and validate JSON files
    for path in [base_path, recent_path, modified_path]:
        if not os.path.exists(path):
            raise FileNotFoundError(f"NVD JSON file not found: {path}")
        with open(path, "r") as f:
            data = json.load(f)
        validate_json(data, schema_path)

    # Merge CVEs: base (2025) + recent (new) + modified (updates)
    cve_dict = {}
    with open(base_path, "r") as f:
        base_json = json.load(f)
        for item in base_json["CVE_Items"]:
            cve_id = item["cve"]["CVE_data_meta"]["ID"]
            cve_dict[cve_id] = item

    with open(recent_path, "r") as f:
        recent_json = json.load(f)
        for item in recent_json["CVE_Items"]:
            cve_id = item["cve"]["CVE_data_meta"]["ID"]
            if cve_id not in cve_dict:
                cve_dict[cve_id] = item

    with open(modified_path, "r") as f:
        modified_json = json.load(f)
        for item in modified_json["CVE_Items"]:
            cve_id = item["cve"]["CVE_data_meta"]["ID"]
            cve_dict[cve_id] = item

    # Extract CVE data from merged CVEs
    merged_cves = list(cve_dict.values())
    return [
        {
            "cve": item["cve"]["CVE_data_meta"]["ID"],
            "score": item["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]
            if "baseMetricV3" in item["impact"] else 0.0
        }
        for item in merged_cves
        if "impact" in item and "baseMetricV3" in item["impact"]
    ]

def parse_kev():
    """Parse CISA KEV CSV to extract exploited CVEs.

    Returns:
        list: List of dicts with CVE IDs and scores.
    """
    df = pd.read_csv("data/kev.csv")
    return [{"cve": cve, "score": 10.0} for cve in df["cveID"]]  # Assume max score for exploited vulns

def parse_attack():
    """Parse MITRE ATT&CK JSON to extract techniques.

    Returns:
        list: List of dicts with technique IDs and scores.
    """
    with open("data/attack.json", "r") as f:
        data = json.load(f)
    return [{"technique": obj["external_references"][0]["external_id"], "score": 5.0}  # Placeholder score
            for obj in data["objects"] if obj["type"] == "attack-pattern"]

def parse_cic():
    """Parse CIC-IDS2017 CSV to extract attack frequencies.

    Returns:
        list: List of dicts with attack labels and their frequencies.
    """
    csv_path = os.path.join("data", "cic_ids2017.csv")
    if not os.path.exists(csv_path):
        extracted_csvs = [f for f in os.listdir("data") if f.endswith('.csv') and 'WorkingHours' in f]
        if extracted_csvs:
            csv_path = os.path.join("data", extracted_csvs[0])
            print(f"Using {csv_path} for CIC-IDS2017 parsing")
        else:
            raise FileNotFoundError("No CIC-IDS2017 CSV files found in data/ directory")
    
    df = pd.read_csv(csv_path)
    attacks = df[" Label"].value_counts().to_dict()
    return [{"attack": label, "score": freq / 1000} for label, freq in attacks.items() if label != "BENIGN"]

def parse_stratosphere():
    """Parse Stratosphere IPS summary CSV to extract risk indicators.

    Returns:
        list: List of dicts with attack labels and scores.
    """
    df = pd.read_csv("data/stratosphere.csv")
    return [{"attack": row["label"], "score": 5.0} for _, row in df.iterrows() if row["label"] != "normal"]

def parse_all_datasets():
    """Parse all datasets and return combined risk indicators.

    Returns:
        dict: Dictionary with risk indicators from each source.
    """
    return {
        "nvd": parse_nvd(),
        "kev": parse_kev(),
        "attack": parse_attack(),
        "cic": parse_cic(),
        "stratosphere": parse_stratosphere()
    }