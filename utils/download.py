import logging
import os
import requests
import time
import json
import hashlib
from .schema import download_schema, validate_json
from datetime import datetime, timedelta
from dateutil.relativedelta import relativedelta
from urllib.parse import quote

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Cache directory for NVD API responses
CACHE_DIR = os.path.join("data", "nvd_cache")
CACHE_TTL = 86400  # Cache for 24 hours (in seconds)

def load_api_key_from_file():
    """Load NVD API key from api_keys.json if environment variable is not set."""
    api_keys_path = "api_keys.json"
    try:
        if os.path.exists(api_keys_path):
            with open(api_keys_path, "r") as f:
                api_keys = json.load(f)
            api_key = api_keys.get("NVD_API_KEY")
            if api_key:
                logging.info("Loaded NVD_API_KEY from api_keys.json in download.py")
                return api_key
            else:
                logging.warning("NVD_API_KEY not found in api_keys.json")
        else:
            logging.warning(f"api_keys.json not found at {api_keys_path}")
    except Exception as e:
        logging.error(f"Failed to load NVD_API_KEY from api_keys.json: {e}")
    return None

def download_file(url, output_path, force_refresh=False):
    """Download a file from a URL and save it to the specified path."""
    if os.path.exists(output_path) and not force_refresh:
        file_size = os.path.getsize(output_path)
        if file_size > 0:
            logging.info(f"File {output_path} exists and is {file_size} bytes, skipping download")
            return
        logging.warning(f"File {output_path} exists but is empty, forcing download")
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

def get_cache_path(params):
    """Generate a cache file path based on query parameters."""
    param_str = json.dumps(params, sort_keys=True)
    cache_key = hashlib.sha256(param_str.encode()).hexdigest()
    os.makedirs(CACHE_DIR, exist_ok=True)
    return os.path.join(CACHE_DIR, f"{cache_key}.json")

def is_cache_valid(cache_path):
    """Check if a cache file is valid and within TTL."""
    if not os.path.exists(cache_path):
        return False
    file_mtime = os.path.getmtime(cache_path)
    current_time = time.time()
    return (current_time - file_mtime) < CACHE_TTL

def download_nvd_api(api_url, data_dir, api_key, schema_url=None, schema_path=None, force_refresh=False):
    """Download NVD CVE data for the past 18 months, split by month."""
    try:
        if schema_url and schema_path:
            logging.debug(f"Downloading schema from {schema_url}")
            download_schema(schema_url, schema_path)
        
        # Use provided api_key or fall back to environment variable or api_keys.json
        if not api_key:
            api_key = os.getenv("NVD_API_KEY") or load_api_key_from_file()
        if not api_key:
            logging.warning("No NVD_API_KEY provided, environment variable not set, and not found in api_keys.json. NVD API downloads may fail.")

        headers = {"apiKey": api_key} if api_key else {}
        # Get date ranges for the past 18 months, ending with the previous month
        end_date = (datetime.utcnow().replace(day=1) - timedelta(days=1)).replace(day=1)
        start_date = end_date - relativedelta(months=18)
        
        current_date = start_date
        while current_date <= end_date:
            month_start = current_date.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            month_end = (month_start + relativedelta(months=1) - timedelta(seconds=1))
            output_path = os.path.join(data_dir, f"nvdcve-{month_start.strftime('%Y-%m')}.json")
            
            if os.path.exists(output_path) and not force_refresh:
                file_size = os.path.getsize(output_path)
                if file_size > 0:
                    logging.info(f"File {output_path} exists and is {file_size} bytes, skipping download")
                    current_date += relativedelta(months=1)
                    continue
                logging.warning(f"File {output_path} exists but is empty, forcing download")

            params = {
                "pubStartDate": month_start.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                "pubEndDate": month_end.strftime("%Y-%m-%dT%H:%M:%S.999Z"),
                "resultsPerPage": 2000,
                "startIndex": 0
            }
            all_items = []
            start_index = 0
            results_per_page = params["resultsPerPage"]
            max_results = 10000
            total_results = 0
            retries = 3
            delay = 6 if api_key else 30

            cache_path = get_cache_path(params)
            if is_cache_valid(cache_path) and not force_refresh:
                logging.info(f"Loading cached NVD data from {cache_path}")
                with open(cache_path, "r") as f:
                    data = json.load(f)
                all_items = data.get("vulnerabilities", [])
                total_results = data.get("totalResults", 0)
            else:
                logging.info(f"Fetching NVD CVEs for {month_start.strftime('%Y-%m')}: {params}")
                while True:
                    params["startIndex"] = start_index
                    encoded_params = {
                        k: quote(v, safe=':+-') if k in ["pubStartDate", "pubEndDate"] else v
                        for k, v in params.items()
                    }
                    logging.info(f"Fetching NVD CVEs: startIndex={start_index}, resultsPerPage={results_per_page}")
                    for attempt in range(retries):
                        try:
                            response = requests.get(api_url, headers=headers, params=encoded_params, timeout=10)
                            response.raise_for_status()
                            data = response.json()
                            items = data.get("vulnerabilities", [])
                            all_items.extend(items)
                            total_results = data.get("totalResults", total_results)
                            logging.info(f"Fetched {len(items)} CVEs, total so far: {len(all_items)}/{total_results}")
                            if items:
                                logging.debug(f"First CVE structure: {json.dumps(items[0], indent=2)[:1000]}...")
                            elif not items and not all_items:
                                logging.warning(f"No vulnerabilities in response: {json.dumps(data, indent=2)[:500]}...")
                            break
                        except requests.HTTPError as e:
                            if response.status_code == 400:
                                logging.error(f"Invalid request (e.g., date format): {e}. Response: {response.text}")
                                break
                            elif response.status_code == 404:
                                logging.warning(f"NVD API returned 404: {e}. Response: {response.text}")
                                break
                            elif response.status_code == 429:
                                logging.warning(f"Rate limit exceeded, retrying after {delay} seconds...")
                                time.sleep(delay * (2 ** attempt))
                            else:
                                raise
                        except requests.RequestException as e:
                            logging.error(f"Request failed, retrying after {delay} seconds: {e}")
                            time.sleep(delay * (2 ** attempt))
                    else:
                        logging.error(f"Failed to fetch NVD data after {retries} retries")
                        break

                    if response.status_code in [400, 404]:
                        break
                    if len(all_items) >= total_results or not items or len(all_items) >= max_results:
                        break
                    start_index += results_per_page
                    time.sleep(delay)

                cache_data = {
                    "vulnerabilities": all_items,
                    "totalResults": total_results,
                    "timestamp": datetime.utcnow().isoformat()
                }
                with open(cache_path, "w") as f:
                    json.dump(cache_data, f)
                logging.info(f"Cached NVD data to {cache_path}")

            if not all_items:
                logging.warning(f"No CVEs retrieved for {month_start.strftime('%Y-%m')}. Saving empty dataset.")
            
            nvd_data = {
                "resultsPerPage": results_per_page,
                "startIndex": 0,
                "totalResults": min(total_results, len(all_items)),
                "format": "NVD_CVE",
                "version": "2.0",
                "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                "vulnerabilities": all_items
            }
            
            if schema_path:
                logging.debug(f"Validating NVD data against schema: {schema_path}")
                validate_json(nvd_data, schema_path, skip_on_failure=True)
            
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            with open(output_path, "w") as f:
                json.dump(nvd_data, f)
            logging.info(f"Successfully downloaded {len(all_items)} CVEs to {output_path}")
            
            current_date += relativedelta(months=1)
    except Exception as e:
        logging.error(f"Error processing NVD API data: {e}")

def download_datasets(config, data_dir, force_refresh=False):
    """Download datasets specified in the configuration."""
    api_key = os.getenv("NVD_API_KEY") or load_api_key_from_file()
    if not api_key:
        logging.warning("NVD_API_KEY environment variable not set and not found in api_keys.json. NVD API downloads may fail.")

    for source in config.get("sources", []):
        name = source.get("name", "")
        url = source.get("url", "")
        source_type = source.get("type", "")
        output_file = source.get("output", "")
        schema_url = source.get("schema_url")
        schema_path = source.get("schema_path")
        
        if not all([name, url, source_type]):
            logging.warning(f"Skipping source {name}: missing required fields")
            continue
        
        if not source.get("enabled", True):
            logging.info(f"Skipping disabled source: {name}")
            continue
        
        if source_type in ["file", "json", "csv"]:
            output_path = os.path.join(data_dir, output_file)
            logging.debug(f"Downloading {name} from {url}")
            download_file(url, output_path, force_refresh)
        elif source_type == "json_api":
            if name == "NVD CVE":
                logging.debug(f"Fetching {name} from NVD API {url}")
                download_nvd_api(url, data_dir, api_key, schema_url, schema_path, force_refresh)
            else:
                logging.warning(f"JSON API source type not supported for {name}. Only NVD CVE API is implemented.")
        else:
            logging.warning(f"Unsupported source type '{source_type}' for {name}. Expected 'file', 'json', 'csv', or 'json_api'. Skipping download.")
