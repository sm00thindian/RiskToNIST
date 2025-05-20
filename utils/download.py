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
        extract_to | extract_to (str): Directory to extract the files to.
        output_filename (str, optional): Rename the extracted file to this name.
    """
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_to)
        print(f"Extracted {zip_path} to {extract_to}")
        if output_filename:
            # Rename the first extracted CSV file (assuming one main file)
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

def download_datasets():
    """Download all required datasets."""
    # NVD feeds (ZIP files)
    nvd_feeds = [
        ("https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2025.json.zip", "nvdcve-1.1-2025.json.zip", "nvdcve-1.1-2025.json"),
        ("https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.zip", "nvdcve-1.1-recent.json.zip", "nvdcve-1.1-recent.json"),
        ("https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.zip", "nvdcve-1.1-modified.json.zip", "nvdcve-1.1-modified.json"),
    ]
    for url, zip_filename, output_filename in nvd_feeds:
        zip_path = os.path.join("data", zip_filename)
        download_file(url, zip_filename)
        extract_zip(zip_path, "data", output_filename)
        # Optionally remove the ZIP file
        # os.remove(zip_path)

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
    # Note: The original URL (https://www.unb.ca/cic/datasets/ids-2017/GeneratedLabelledFlows.zip) returns 404
    # Placeholder URL; replace with the correct URL from https://www.unb.ca/cic/datasets/ids-2017.html
    # If registration is required, visit the page, complete the form, and obtain the download link
    cic_url = "http://205.174.165.80/CICDataset/CIC-IDS-2017/Dataset/MachineLearningCSV.zip"  # Outdated, replace with new URL
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
