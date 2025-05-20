"""Utility functions to download risk indicator datasets."""

import os
import requests
import zipfile

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

def extract_zip(zip_path, extract_to):
    """Extract a ZIP file to the specified directory.

    Args:
        zip_path (str): Path to the ZIP file.
        extract_to (str): Directory to extract the files to.
    """
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(extract_to)
    print(f"Extracted {zip_path} to {extract_to}")

def download_datasets():
    """Download all required datasets."""
    # NVD feeds (ZIP files)
    nvd_feeds = [
        ("https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2025.json.zip", "nvdcve-1.1-2025.json.zip"),
        ("https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.zip", "nvdcve-1.1-recent.json.zip"),
        ("https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.zip", "nvdcve-1.1-modified.json.zip"),
    ]
    for url, zip_filename in nvd_feeds:
        zip_path = os.path.join("data", zip_filename)
        download_file(url, zip_filename)
        extract_zip(zip_path, "data")
        # Optionally remove the ZIP file after extraction
        # os.remove(zip_path)

    # Other datasets (direct files)
    other_datasets = [
        ("https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv", "kev.csv"),
        ("https://attack.mitre.org/docs/enterprise-attack.json", "attack.json"),  # Assuming direct JSON
        ("https://www.unb.ca/cic/datasets/ids-2017/GeneratedLabelledFlows.csv", "cic_ids2017.csv"),
        ("https://www.stratosphereips.org/datasets/summary.csv", "stratosphere.csv"),
    ]
    for url, filename in other_datasets:
        download_file(url, filename)
