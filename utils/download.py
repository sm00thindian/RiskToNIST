import json
import os
import requests
import time
from datetime import datetime, timedelta
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def download_datasets(config_path="config.json", data_dir="data"):
    """Download enabled datasets (CSV, JSON, or API) from URLs specified in the config file.

    Args:
        config_path (str): Path to the configuration file.
        data_dir (str): Directory to save downloaded files.
    """
    os.makedirs(data_dir, exist_ok=True)
    
    try:
        with open(config_path, "r") as f:
            config = json.load(f)
    except Exception as e:
        logging.error(f"Failed to read {config_path}: {e}")
        return
    
    for source in config["sources"]:
        if not source.get("enabled", False):
            logging.info(f"Skipping disabled source: {source['name']}")
            continue
        
        source_type = source.get("type")
        url = source["url"]
        name = source["name"].replace(" ", "_").lower()
        
        if source_type in ["csv", "json"]:
            file_ext = source_type
            filename = f"{name}.{file_ext}"
            filepath = os.path.join(data_dir, filename)
            if not os.path.exists(filepath):
                try:
                    response = requests.get(url, timeout=10)
                    response.raise_for_status()
                    with open(filepath, "wb") as f:
                        f.write(response.content)
                    logging.info(f"Downloaded {filename}")
                except requests.RequestException as e:
                    logging.error(f"Error downloading {filename}: {e}")
            else:
                logging.info(f"{filename} already exists, skipping download.")
        
        elif source_type == "api" and source["name"] == "NVD CVE":
            api_key = os.environ.get("NVD_API_KEY")
            if not api_key:
                logging.error("NVD_API_KEY environment variable not set.")
                continue
            
            headers = {"apiKey": api_key}
            results_per_page = 2000  # NVD API max
            start_date = datetime(2025, 1, 1)
            end_date = datetime.now()
            delta = timedelta(days=30)
            
            # Output files
            base_filepath = os.path.join(data_dir, "nvdcve-1.1-2025.json")
            recent_filepath = os.path.join(data_dir, "nvdcve-1.1-recent.json")
            modified_filepath = os.path.join(data_dir, "nvdcve-1.1-modified.json")
            
            if all(os.path.exists(p) for p in [base_filepath, recent_filepath, modified_filepath]):
                logging.info("NVD JSON files already exist, skipping download.")
                continue
            
            cve_items = []
            current_start = start_date
            request_count = 0
            while current_start < end_date:
                current_end = min(current_start + delta, end_date)
                params = {
                    "lastModStartDate": current_start.strftime("%Y-%m-%dT%H:%M:%S.000"),
                    "lastModEndDate": current_end.strftime("%Y-%m-%dT%H:%M:%S.999"),
                    "resultsPerPage": results_per_page,
                    "startIndex": 0
                }
                
                while True:
                    try:
                        response = requests.get(url, headers=headers, params=params, timeout=10)
                        request_count += 1
                        if response.status_code == 404:
                            logging.info(f"No CVEs for {current_start} to {current_end}, continuing...")
                            break
                        response.raise_for_status()
                        data = response.json()
                        vulnerabilities = data.get("vulnerabilities", [])
                        cve_items.extend(vulnerabilities)
                        logging.info(f"Fetched {len(vulnerabilities)} CVEs for {current_start} to {current_end}")
                        total_results = data.get("totalResults", 0)
                        params["startIndex"] += results_per_page
                        if params["startIndex"] >= total_results:
                            break
                        if request_count % 5 == 0:
                            time.sleep(3)  # Rate limit: 50 requests per 30 seconds
                    except requests.RequestException as e:
                        logging.error(f"Error fetching NVD CVEs for {current_start} to {current_end}: {e}")
                
                current_start = current_end + timedelta(seconds=1)
            
            # Save NVD data
            with open(base_filepath, "w") as f:
                json.dump({"CVE_Items": cve_items}, f, indent=2)
            logging.info(f"Saved {base_filepath}")
            
            recent_date = end_date - timedelta(days=8)
            recent_items = [item for item in cve_items if datetime.strptime(item["cve"]["published"], "%Y-%m-%dT%H:%M:%S.%f") >= recent_date]
            with open(recent_filepath, "w") as f:
                json.dump({"CVE_Items": recent_items}, f, indent=2)
            logging.info(f"Saved {recent_filepath}")
            
            modified_items = [item for item in cve_items if datetime.strptime(item["cve"]["lastModified"], "%Y-%m-%dT%H:%M:%S.%f") >= recent_date]
            with open(modified_filepath, "w") as f:
                json.dump({"CVE_Items": modified_items}, f, indent=2)
            logging.info(f"Saved {modified_filepath}")