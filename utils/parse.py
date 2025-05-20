"""Utility functions to parse risk indicator datasets."""

import json
import pandas as pd
import os

def parse_nvd():
    """Parse NVD JSON feed to extract CVE IDs and CVSS scores.

    Returns:
        list: List of dicts with CVE ID and CVSS score.
    """
    with open("data/nvd.json", "r") as f:
        data = json.load(f)
    return [{"cve": item["cve"]["CVE_data_meta"]["ID"], "score": item["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]}
            for item in data["CVE_Items"] if "baseMetricV3" in item["impact"]]

def parse_kev():
    """Parse CISA KEV CSV to extract exploited CVEs.

    Returns:
        list: List of CVE IDs.
    """
    df = pd.read_csv("data/kev.csv")
    return [{"cve": cve, "score": 10.0} for cve in df["cveID"]]  # Assume max score for exploited vulns

def parse_attack():
    """Parse MITRE ATT&CK JSON to extract techniques.

    Returns:
        list: List of technique IDs.
    """
    with open("data/attack.json", "r") as f:
        data = json.load(f)
    return [{"technique": obj["external_references"][0]["external_id"], "score": 5.0}  # Placeholder score
             for obj in data["objects"] if obj["type"] == "attack-pattern")]

def parse_cic():
    """Parse CIC-IDS2017 CSV to extract attack frequencies.

    Returns:
        list: List of attack labels and their frequencies.
    """
    df = pd.read_csv("data/cic_ids2017.csv")
    attacks = df["Label"].value_counts().to_dict()
    return [{"attack": label, "score": freq / 1000} for label, freq in attacks.items() if label != "BENIGN"]

def parse_stratosphere():
    """Parse Stratosphere IPS summary CSV to extract risk indicators.

    Returns:
        list: List of risk indicators (simplified).
    """
    df = pd.read_csv("data/stratosphere.csv")  # Assumes a summary CSV exists
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
