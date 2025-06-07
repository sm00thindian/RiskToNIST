import logging
import os
import requests
import time
import json
import hashlib
import shutil
from datetime import datetime, timedelta
from dateutil.relativedelta import relativedelta
from urllib.parse import quote
from concurrent.futures import ThreadPoolExecutor
from .schema import download_schema, validate_json

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Cache directory for NVD API responses
CACHE_DIR = os.path.join("data", "nvd_cache")
CACHE_TTL = 86400  # Cache for 24 hours (in seconds)

def load_api_key_from_file():
    """Load NVD API key from api_keys.json if environment variable is not set.

    Returns:
        str: API key if found, None otherwise.
    """
    api_keys_path = "api_keys.json"
    try:
        if os.path.exists(api_keys_path):
            with open(api_keys_path, "r") as f:
                api_keys = json.load(f)
            api_key = api_keys.get("NVD_API_KEY")
            if api_key:
                logging.info("Loaded NVD_API_KEY from api_keys.json")
                return api_key
            else:
                logging.warning("NVD_API_KEY not found in api_keys.json")
        else:
            logging.warning(f"api_keys.json not found at {api_keys_path}")
    except Exception as e:
        logging.error(f"Failed to load NVD_API_KEY: {e}")
    return None

def download_file(url, output_path, force_refresh=False):
    """Download a file from a URL and save it to the specified path.

    Args:
        url (str): URL to download from.
        output_path (str): Path to save the downloaded file.
        force_refresh (bool): If True, re-download even if file exists.

    Raises:
        requests.RequestException: If the download fails.
    """
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
    """Generate a cache file path based on query parameters.

    Args:
        params (dict): Query parameters for the API request.

    Returns:
        str: Path to the cache file.
    """
    param_str = json.dumps(params, sort_keys=True)
    cache_key = hashlib.sha256(param_str.encode()).hexdigest()
    os.makedirs(CACHE_DIR, exist_ok=True)
    return os.path.join(CACHE_DIR, f"{cache_key}.json")

def is_cache_valid(cache_path):
    """Check if a cache file is valid and within TTL.

    Args:
        cache_path (str): Path to the cache file.

    Returns:
        bool: True if cache is valid, False otherwise.
    """
    if not os.path.exists(cache_path):
        return False
    file_mtime = os.path.getmtime(cache_path)
    current_time = time.time()
    return (current_time - file_mtime) < CACHE_TTL

def get_last_saturday():
    """Calculate the date of the last Saturday before today.

    Returns:
        datetime: Date of the last Saturday.
    """
    today = datetime.utcnow().replace(hour=23, minute=59, second=59, microsecond=999999)
    days_since_saturday = (today.weekday() + 1) % 7
    if days_since_saturday == 0:
        days_since_saturday = 7
    return today - timedelta(days=days_since_saturday)

def fetch_nvd_data(api_url, headers, params, cache_path, output_path, schema_path, force_refresh, retries=3, delay=6):
    """Fetch NVD CVE data for a given date range and save to output path.

    Args:
        api_url (str): NVD API URL.
        headers (dict): Request headers.
        params (dict): Query parameters.
        cache_path (str): Path to cache file.
        output_path (str): Path to save output JSON.
        schema_path (str): Path to JSON schema for validation.
        force_refresh (bool): If True, ignore cache.
        retries (int): Number of retry attempts for failed requests.
        delay (int): Delay between retries in seconds.

    Returns:
        tuple: (int, int) Number of CVEs fetched and total results.
    """
    all_items = []
    total_results = 0
    start_index = 0
    results_per_page = params["resultsPerPage"]
    max_results = 10000

    if is_cache_valid(cache_path) and not force_refresh:
        logging.info(f"Loading cached NVD data from {cache_path}")
        with open(cache_path, "r") as f:
            data = json.load(f)
        all_items = data.get("vulnerabilities", [])
        total_results = data.get("totalResults", 0)
    else:
        while True:
            params["startIndex"] = start_index
            encoded_params = {k: quote(v, safe=':+-') if k in ["pubStartDate", "pubEndDate"] else v for k, v in params.items()}
            for attempt in range(retries):
                try:
                    response = requests.get(api_url, headers=headers, params=encoded_params, timeout=10)
                    response.raise_for_status()
                    data = response.json()
                    items = data.get("vulnerabilities", [])
                    all_items.extend(items)
                    total_results = data.get("totalResults", total_results)
                    logging.info(f"Fetched {len(items)} CVEs, total so far: {len(all_items)}/{total_results}")
                    break
                except requests.HTTPError as e:
                    if response.status_code in [400, 404]:
                        logging.warning(f"NVD API returned {response.status_code}: {e}. Response: {response.text}")
                        return 0, 0
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
                return 0, 0

            if len(all_items) >= total_results or not items or len(all_items) >= max_results:
                break
            start_index += results_per_page
            time.sleep(delay)

        cache_data = {"vulnerabilities": all_items, "totalResults": total_results, "timestamp": datetime.utcnow().isoformat()}
        with open(cache_path, "w") as f:
            json.dump(cache_data, f)
        logging.info(f"Cached NVD data to {cache_path}")

    if not all_items:
        logging.warning(f"No CVEs retrieved for {params['pubStartDate']}. Saving empty dataset.")

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
    return len(all_items), total_results

def download_nvd_api(api_url, data_dir, api_key, schema_url=None, schema_path=None, force_refresh=False, total_months=6, max_days=60, default_days=7, end_date_reference="last_saturday"):
    """Download NVD CVE data for the specified period in increments, using parallel processing.

    Args:
        api_url (str): NVD API URL.
        data_dir (str): Directory to save downloaded files.
        api_key (str): NVD API key.
        schema_url (str): URL for JSON schema.
        schema_path (str): Path to JSON schema file.
        force_refresh (bool): If True, re-download data.
        total_months (int): Number of months to query.
        max_days (int): Maximum days per increment.
        default_days (int): Default days per increment.
        end_date_reference (str): Reference for end date (e.g., "last_saturday").

    Returns:
        list: Paths to downloaded files.
    """
    if schema_url and schema_path:
        logging.debug(f"Downloading schema from {schema_url}")
        download_schema(schema_url, schema_path)

    api_key = api_key or os.getenv("NVD_API_KEY") or load_api_key_from_file()
    headers = {"apiKey": api_key} if api_key else {}
    delay = 6 if api_key else 30

    end_date = get_last_saturday() if end_date_reference.lower() == "last_saturday" else datetime.utcnow().replace(hour=23, minute=59, second=59, microsecond=999999)
    total_months = max(1, min(int(total_months), 24))
    start_date = end_date - relativedelta(months=total_months) + timedelta(days=1)
    max_days = max(1, int(max_days))
    default_days = max(1, min(int(default_days), max_days))

    logging.info(f"Fetching NVD CVE data from {start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')} in {default_days}-day increments (max {max_days} days)")

    date_ranges = []
    current_date = start_date
    while current_date <= end_date:
        period_end = min(current_date + timedelta(days=default_days - 1, hours=23, minutes=59, seconds=59, milliseconds=999), end_date)
        if (period_end - current_date).days > max_days:
            period_end = current_date + timedelta(days=max_days - 1, hours=23, minutes=59, seconds=59, milliseconds=999)
        output_path = os.path.join(data_dir, f"nvdcve-{current_date.strftime('%Y-%m-%d')}.json")
        if not (os.path.exists(output_path) and os.path.getsize(output_path) > 0 and not force_refresh):
            date_ranges.append((current_date, period_end, output_path))
        current_date = period_end + timedelta(days=1)

    def fetch_wrapper(date_range):
        start, end, path = date_range
        params = {
            "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.999Z"),
            "resultsPerPage": 2000,
            "startIndex": 0
        }
        cache_path = get_cache_path(params)
        cve_count, total = fetch_nvd_data(api_url, headers, params, cache_path, path, schema_path, force_refresh, delay=delay)
        return path, cve_count, total

    downloaded_files = []
    with ThreadPoolExecutor(max_workers=4) as executor:
        results = executor.map(fetch_wrapper, date_ranges)
        for path, cve_count, total in results:
            if cve_count > 0:
                downloaded_files.append(path)
                logging.info(f"Successfully downloaded {cve_count} CVEs to {path}")

    if os.path.exists(CACHE_DIR):
        shutil.rmtree(CACHE_DIR)
        logging.info(f"Cleaned up NVD cache directory: {CACHE_DIR}")

    return downloaded_files

def download_datasets(config, data_dir, force_refresh=False):
    """Download datasets specified in the configuration.

    Args:
        config (dict): Configuration dictionary from config.json.
        data_dir (str): Directory to save downloaded files.
        force_refresh (bool): If True, re-download data.

    Returns:
        list: Paths to downloaded files.
    """
    api_key = os.getenv("NVD_API_KEY") or load_api_key_from_file()
    downloaded_files = []

    for source in config.get("sources", []):
        name = source.get("name", "")
        url = source.get("url", "")
        source_type = source.get("type", "")
        output_file = source.get("output", "")
        schema_url = source.get("schema_url")
        schema_path = source.get("schema_path")
        enabled = source.get("enabled", True)
        total_months = source.get("total_months", 6)
        max_days = source.get("max_days", 60)
        default_days = source.get("default_days", 7)
        end_date_reference = source.get("end_date_reference", "last_saturday")

        if not all([name, url, source_type]):
            logging.warning(f"Skipping source {name}: missing required fields")
            continue

        if not enabled:
            logging.info(f"Skipping disabled source: {name}")
            continue

        if source_type in ["file", "json", "csv"]:
            output_path = os.path.join(data_dir, output_file)
            logging.debug(f"Downloading {name} from {url}")
            download_file(url, output_path, force_refresh)
            downloaded_files.append(output_path)
        elif source_type == "json_api":
            if name == "NVD CVE":
                logging.debug(f"Fetching {name} from NVD API {url}")
                files = download_nvd_api(url, data_dir, api_key, schema_url, schema_path, force_refresh, total_months, max_days, default_days, end_date_reference)
                downloaded_files.extend(files)
            else:
                logging.warning(f"JSON API source type not supported for {name}. Only NVD CVE API is implemented.")
        else:
            logging.warning(f"Unsupported source type '{source_type}' for {name}. Skipping download.")

    return downloaded_files
