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

    # Paths to the extracted NVD JSON files
    base_path = os.path.join("data", "nvdcve-1.1-2025.json")
    recent_path = os.path.join("data", "nvdcve-1.1-recent.json")
    modified_path = os.path.join("data", "nvdcve-1.1-modified.json")

    # Load and validate JSON files
    with open(base_path, "r") as f:
        base_json = json.load(f)
    validate_json(base_json, schema_path)

    with open(recent_path, "r") as f:
        recent_json = json.load(f)
    validate_json(recent_json, schema_path)

    with open(modified_path, "r") as f:
        modified_json = json.load(f)
    validate_json(modified_json, schema_path)

    # Merge CVEs: base (2025) + recent (new) + modified (updates)
    cve_dict = {}
    for item in base_json['CVE_Items']:
        cve_id = item['cve']['CVE_data_meta']['ID']
        cve_dict[cve_id] = item

    for item in recent_json['CVE_Items']:
        cve_id = item['cve']['CVE_data_meta']['ID']
        if cve_id not in cve_dict:
            cve_dict[cve_id] = item

    for item in modified_json['CVE_Items']:
        cve_id = item['cve']['CVE_data_meta']['ID']
        if cve_id in cve_dict:
            cve_dict[cve_id] = item

    # Extract CVE data from merged CVEs
    merged_cves = list(cve_dict.values())
    return [{"cve": item["cve"]["CVE_data_meta"]["ID"], "score": item["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]}
            for item in merged_cves if "baseMetricV3" in item["impact"]]

# Below are placeholder functions for other datasets; update as needed
def parse_kev():
    """Parse CISA KEV CSV."""
    df = pd.read_csv(os.path.join("data", "kev.csv"))
    return df[["cveID"]].to_dict("records")

def parse_attack():
    """Parse MITRE ATT&CK JSON."""
    with open(os.path.join("data", "attack.json"), "r") as f:
        data = json.load(f)
    return data.get("objects", [])

def parse_cic():
    """Parse CIC IDS2017 CSV."""
    df = pd.read_csv(os.path.join("data", "cic_ids2017.csv"))
    return df.to_dict("records")

def parse_stratosphere():
    """Parse Stratosphere IPS CSV."""
    df = pd.read_csv(os.path.join("data", "stratosphere.csv"))
    return df.to_dict("records")

def parse_all_datasets():
    """Parse all datasets and return them in a structured format."""
    return {
        "nvd": parse_nvd(),
        "kev": parse_kev(),
        "attack": parse_attack(),
        "cic": parse_cic(),
        "stratosphere": parse_stratosphere(),
    }
