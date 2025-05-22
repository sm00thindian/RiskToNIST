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
    try:
        download_schema(schema_url, schema_path)
    except Exception as e:
        print(f"Warning: Failed to download schema: {e}")
        print("Continuing without schema validation...")

    # Paths to the NVD JSON files
    base_path = os.path.join("data", "nvdcve-1.1-2025.json")
    recent_path = os.path.join("data", "nvdcve-1.1-recent.json")
    modified_path = os.path.join("data", "nvdcve-1.1-modified.json")

    # Load JSON files
    cve_dict = {}
    for path in [base_path, recent_path, modified_path]:
        if not os.path.exists(path):
            print(f"Warning: {path} not found, skipping.")
            continue
        try:
            with open(path, "r") as f:
                data = json.load(f)
            # Validate JSON if schema is available
            validate_json(data, schema_path)
            for item in data.get("CVE_Items", []):
                cve_id = item["cve"]["CVE_data_meta"]["ID"]
                cve_dict[cve_id] = item
        except json.JSONDecodeError as e:
            print(f"Warning: Failed to parse {path}: {e}")
            continue

    # Extract CVE data from merged CVEs
    merged_cves = list(cve_dict.values())
    return [
        {
            "cve": item["cve"]["CVE_data_meta"]["ID"],
            "score": item["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]
            if "impact" in item and "baseMetricV3" in item["impact"] else 0.0
        }
        for item in merged_cves
        if "cve" in item and "CVE_data_meta" in item and "ID" in item["cve"]["CVE_data_meta"]
    ]

def parse_kev():
    """Parse CISA KEV CSV to extract exploited CVEs.

    Returns:
        list: List of dicts with CVE IDs and scores.
    """
    csv_path = os.path.join("data", "kev.csv")
    if not os.path.exists(csv_path):
        print(f"Warning: {csv_path} not found, skipping KEV parsing.")
        return []
    try:
        df = pd.read_csv(csv_path)
        if "cveID" not in df.columns:
            print(f"Warning: 'cveID' column not found in {csv_path}, skipping KEV parsing.")
            return []
        return [{"cve": cve, "score": 10.0} for cve in df["cveID"]]  # Assume max score for exploited vulns
    except pd.errors.EmptyDataError:
        print(f"Warning: {csv_path} is empty or invalid, skipping KEV parsing.")
        return []

def parse_attack():
    """Parse MITRE ATT&CK JSON to extract techniques.

    Returns:
        list: List of dicts with technique IDs and scores.
    """
    json_path = os.path.join("data", "attack.json")
    if not os.path.exists(json_path):
        print(f"Warning: {json_path} not found, skipping ATT&CK parsing.")
        return []
    try:
        with open(json_path, "r") as f:
            data = json.load(f)
        return [{"technique": obj["external_references"][0]["external_id"], "score": 5.0}  # Placeholder score
                for obj in data["objects"] if obj["type"] == "attack-pattern"]
    except json.JSONDecodeError:
        print(f"Warning: {json_path} is invalid JSON, skipping ATT&CK parsing.")
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