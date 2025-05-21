"""Utility functions to download risk indicator datasets."""

import os
import requests
import zipfile
import json
from datetime import datetime, timedelta

def download_file(url, filename):
    """Download a file from a URL and save it to the data directory.

    Args:
        url (str): URL of the file to download.
        filename (str): Name of the file to save in the data directory.
    """
    filepath = os.path.join("data", filename)
    if not os.path.exists(filepath):
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            with open(filepath, "wb") as f:
                f.write(response.content)
            print(f"Downloaded {filename}")
        except requests.RequestException as e:
            print(f"Error downloading {filename}: {e}")
            raise
    else:
        print(f"{filename} already exists, skipping download.")

def extract_zip(zip_path, extract_to, output_filename=None):
    """Extract a ZIP file to the specified directory, optionally renaming the output.

    Args:
        zip_path (str): Path to the ZIP file.
        extract_to (str): Directory to extract the files to.
        output_filename (str, optional): Rename the extracted file to this name.
    """
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_to)
        print(f"Extracted {zip_path} to {extract_to}")
        if output_filename:
            extracted_files = [f for f in os.listdir(extract_to) if f.endswith('.csv') and not f.startswith('__MACOSX')]
            if extracted_files:
                os.rename(
                    os.path.join(extract_to, extracted_files[0]),
                    os.path.join(extract_to, output_filename)
                )
                print(f"Renamed extracted file to {output_filename}")
            else:
                print(f"Warning: No CSV files found in {zip_path}")
    except zipfile.BadZipFile as e:
        print(f"Error extracting {zip_path}: {e}")
        raise

def download_nvd_cves():
    """Download NVD CVE data using the 2.0 API, saving as JSON files."""
    # Use provided API key or environment variable
    api_key = os.environ.get("NVD_API_KEY", "Go-Get-A-Key")
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {"apiKey": api_key}
    results_per_page = 2000  # Maximum allowed by NVD API
    start_date = datetime(2025, 1, 1)
    end_date = datetime(2025, 5, 21)  # Current date
    delta = timedelta(days=120)  # Maximum date range per request

    # Initialize JSON files
    base_filepath = os.path.join("data", "nvdcve-1.1-2025.json")
    recent_filepath = os.path.join("data", "nvdcve-1.1-recent.json")
    modified_filepath = os.path.join("data", "nvdcve-1.1-modified.json")

    # Check if files already exist
    if all(os.path.exists(p) for p in [base_filepath, recent_filepath, modified_filepath]):
        print("NVD JSON files already exist, skipping download.")
        return

    # Fetch CVEs in 120-day chunks
    cve_items = []
    current_start = start_date
    while current_start < end_date:
        current_end = min(current_start + delta, end_date)
        params = {
            "lastModStartDate": current_start.strftime("%Y-%m-%dT00:00:00.000"),
            "lastModEndDate": current_end.strftime("%Y-%m-%dT23:59:59.999"),
            "resultsPerPage": results_per_page,
            "startIndex": 0
        }

        while True:
            try:
                response = requests.get(base_url, headers=headers, params=params, timeout=10)
                response.raise_for_status()
                data = response.json()
                cve_items.extend(data.get("vulnerabilities", []))
                total_results = data.get("totalResults", 0)
                params["startIndex"] += results_per_page
                if params["startIndex"] >= total_results:
                    break
            except requests.RequestException as e:
                print(f"Error fetching NVD CVEs: {e}")
                raise

        current_start = current_end + timedelta(seconds=1)

    # Save as 2025 base file (all CVEs)
    with open(base_filepath, "w") as f:
        json.dump({"CVE_Items": cve_items}, f)
    print(f"Saved {base_filepath}")

    # Save recent and modified files (simplified, as API covers updates)
    # Recent: CVEs published in the last 8 days
    recent_date = datetime(2025, 5, 13)  # 8 days before May 21, 2025
    recent_items = [item for item in cve_items if datetime.strptime(item["cve"]["published"], "%Y-%m-%dT%H:%M:%S.%f") >= recent_date]
    with open(recent_filepath, "w") as f:
        json.dump({"CVE_Items": recent_items}, f)
    print(f"Saved {recent_filepath}")

    # Modified: CVEs modified in the last 8 days
    modified_items = [item for item in cve_items if datetime.strptime(item["cve"]["lastModified"], "%Y-%m-%dT%H:%M:%S.%f") >= recent_date]
    with open(modified_filepath, "w") as f:
        json.dump({"CVE_Items": modified_items}, f)
    print(f"Saved {modified_filepath}")

def download_datasets():
    """Download all required datasets."""
    # Download NVD CVEs via API
    download_nvd_cves()

    # CISA KEV Catalog (CSV)
    download_file(
        "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv",
        "kev.csv"
    )

    # MITRE ATT&CK (JSON, potentially ZIP)
    attack_url = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
    attack_filename = "attack.json"
    try:
        download_file(attack_url, attack_filename)
    except requests.RequestException:
        # Fallback to ZIP if direct JSON fails
        attack_zip_url = "https://attack.mitre.org/docs/ATTACK_Domain_v15.0_JSON.zip"
        attack_zip_filename = "attack.zip"
        zip_path = os.path.join("data", attack_zip_filename)
        download_file(attack_zip_url, attack_zip_filename)
        extract_zip(zip_path, "data", attack_filename)
        # os.remove(zip_path)

    # CIC-IDS2017 (ZIP containing CSVs)
    # Placeholder URL; replace with the correct URL from https://www.unb.ca/cic/datasets/ids-2017.html
    cic_url = "http://205.174.165.80/CICDataset/CIC-IDS-2017/Dataset/MachineLearningCSV.zip"
    cic_zip_filename = "cic_ids2017.zip"
    cic_output_filename = "cic_ids2017.csv"
    zip_path = os.path.join("data", cic_zip_filename)
    try:
        download_file(cic_url, cic_zip_filename)
        extract_zip(zip_path, "data", cic_output_filename)
        # os.remove(zip_path)
    except requests.RequestException as e:
        print(f"Failed to download CIC-IDS2017: {e}")
        print("Please visit https://www.unb.ca/cic/datasets/ids-2017.html to obtain the correct URL or register for access.")
        print("Update the 'cic_url' variable in download.py with the new URL and re-run.")
        raise

    # Stratosphere IPS (CSV, assuming CTU-13 summary)
    download_file(
        "https://mcfp.felk.cvut.cz/publicDatasets/CTU-13-Dataset/CTU-13-Dataset.csv",
        "stratosphere.csv"
    )