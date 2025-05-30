import logging
import os
import requests
import time
import json
from .schema import download_schema, validate_json
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def download_file(url, output_path, force_refresh=False):
    """Download a file from a URL and save it to the specified path."""
    if os.path.exists(output_path) and not force_refresh:
        logging.info(f"File {output_path} already exists, skipping download")
        return
    try:
        response = requests.get(url, stream=True, timeout=30)
        response.raise_for_status()
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
        logging.info(f"Successfully downloaded {url} to {output_path}")
    except requests.RequestException as e:
        logging.error(f"Failed to download {url}: {e}")

def download_nvd_api(api_url, output_path, api_key, schema_url=None, schema_path=None, force_refresh=False):
    """Download CVE data from the NVD API, validate against schema, and save as JSON."""
    if os.path.exists(output_path) and not force_refresh:
        logging.info(f"File {output_path} already exists, skipping NVD API download")
        return
    try:
        if schema_url and schema_path:
            logging.debug(f"Downloading schema from {schema_url}")
            download_schema(schema_url, schema_path)
        
        headers = {"apiKey": api_key} if api_key else {}
        params = {
            "pubStartDate": "2023-01-01T00:00:00:000 UTC-05:00",
            "pubEndDate": "2024-12-31T23:59:59:999 UTC-05:00",
            "resultsPerPage": 200
        }
        all_items = []
        start_index = 0
        results_per_page = params["resultsPerPage"]
        max_results = 1000  # Limit for testing
        total_results = 0  # Initialize to avoid reference error

        while True:
            params["startIndex"] = start_index
            logging.info(f"Fetching NVD CVEs: startIndex={start_index}, resultsPerPage={results_per_page}")
            try:
                response = requests.get(api_url, headers=headers, params=params, timeout=30)
                response.raise_for_status()
            except requests.HTTPError as e:
                if response.status_code == 404:
                    logging.warning(f"NVD API returned 404, no data available: {e}")
                    break
                raise
            data = response.json()
            items = data.get("vulnerabilities", [])
            all_items.extend(items)
            total_results = data.get("totalResults", total_results)
            logging.info(f"Fetched {len(items)} CVEs, total so far: {len(all_items)}/{total_results}")

            if len(all_items) >= total_results or not items or len(all_items) >= max_results:
                break
            start_index += params["resultsPerPage"]
            time.sleep(6)

        nvd_data = {
            "resultsPerPage": results_per_page,
            "startIndex": 0,
            "totalResults": min(total_results, len(all_items)),
            "format": "NVD_CVE",
            "version": "2.0",
            "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000"),
            "vulnerabilities": all_items
        }
        
        if schema_path:
            logging.debug(f"Validating NVD data against schema: {schema_path}")
            validate_json(nvd_data, schema_path, skip_on_failure=True)
        
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(nvd_data, f)
        logging.info(f"Successfully downloaded {len(all_items)} CVEs from NVD API to {output_path}")
    except requests.RequestException as e:
        logging.error(f"Failed to download from NVD API {api_url}: {e}")
    except Exception as e:
        logging.error(f"Error processing NVD API data: {e}")

def download_datasets(config, data_dir, force_refresh=False):
    """Download datasets specified in the configuration."""
    api_key = os.getenv("NVD_API_KEY")
    if not api_key:
        logging.warning("NVD_API_KEY environment variable not set. NVD API downloads may fail.")

    for source in config.get("sources", []):
        name = source.get("name", "")
        url = source.get("url", "")
        source_type = source.get("type", "")
        output_file = source.get("output", "")
        schema_url = source.get("schema_url")
        schema_path = source.get("schema_path")
        
        if not all([name, url, source_type, output_file]):
            logging.warning(f"Skipping source {name}: missing required fields")
            continue
        
        if not source.get("enabled", True):
            logging.info(f"Skipping disabled source: {name}")
            continue
        
        output_path = os.path.join(data_dir, output_file)
        
        if source_type in ["file", "json", "csv"]:
            logging.debug(f"Downloading {name} from {url}")
            download_file(url, output_path, force_refresh)
        elif source_type == "json_api":
            if name == "NVD CVE":
                logging.debug(f"Fetching {name} from NVD API {url}")
                download_nvd_api(url, output_path, api_key, schema_url, schema_path, force_refresh)
            else:
                logging.warning(f"JSON API source type not supported for {name}. Only NVD CVE API is implemented.")
        else:
            logging.warning(f"Unsupported source type '{source_type}' for {name}. Expected 'file', 'json', 'csv', or 'json_api'. Skipping download.")
