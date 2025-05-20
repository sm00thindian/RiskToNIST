"""Utility functions to download risk indicator datasets."""

import os
import requests

def download_file(url, filename):
    """Download a file from a URL and save it to the data directory.

    Args:
        url (str): URL of the file to download.
        filename (str): Name of the file to save in the data directory.
    """
    filepath = os.path.join("data", filename)
    if not os.path.exists(filepath):
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        with open(filepath, "wb") as f:
            f.write(response.content)
        print(f"Downloaded {filename}")
    else:
        print(f"{filename} already exists, skipping download.")

def download_datasets():
    """Download all required datasets."""
    datasets = [
        # NIST NVD JSON feed (example URL, replace with current feed)
        ("https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json", "nvd.json"),
        # CISA KEV Catalog CSV
        ("https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv", "kev.csv"),
        # MITRE ATT&CK JSON (example URL, replace with current version)
        ("https://attack.mitre.org/docs/ATTACK_Domain_v14.1_JSON.zip", "attack.zip"),
        # CIC-IDS2017 CSV (example file, adjust URL as needed)
        ("https://www.unb.ca/cic/datasets/ids-2017/GeneratedLabelledFlows.csv", "cic_ids2017.csv"),
        # Stratosphere IPS summary (example, assumes CSV summary exists)
        ("https://www.stratosphereips.org/datasets/summary.csv", "stratosphere.csv"),
    ]

    for url, filename in datasets:
        download_file(url, filename)

    # Special handling for ATT&CK ZIP file (unzip if needed)
    if os.path.exists("data/attack.zip"):
        import zipfile
        with zipfile.ZipFile("data/attack.zip", "r") as zip_ref:
            zip_ref.extractall("data")
        os.rename("data/enterprise-attack.json", "data/attack.json")
        os.remove("data/attack.zip")
