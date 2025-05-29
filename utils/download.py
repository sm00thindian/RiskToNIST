import os
import requests
import logging
import time

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def download_file(url, output_path, retries=3, delay=5):
    """Download a file from a URL to the specified path with retries.

    Args:
        url (str): URL to download from.
        output_path (str): Local path to save the file.
        retries (int): Number of retry attempts.
        delay (int): Delay between retries in seconds.

    Returns:
        bool: True if download succeeded, False otherwise.
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    for attempt in range(retries):
        try:
            response = requests.get(url, timeout=30, stream=True)
            response.raise_for_status()
            
            with open(output_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
            
            logging.info(f"Successfully downloaded {url} to {output_path}")
            return True
        
        except requests.exceptions.RequestException as e:
            logging.warning(f"Attempt {attempt + 1}/{retries} failed for {url}: {e}")
            if attempt < retries - 1:
                time.sleep(delay)
            else:
                logging.error(f"Failed to download {url} after {retries} attempts")
                return False

def download_datasets(config, data_dir="data"):
    """Download datasets specified in the configuration.

    Args:
        config (dict): Configuration dictionary with sources.
        data_dir (str): Directory to save downloaded files.
    """
    os.makedirs(data_dir, exist_ok=True)
    
    for source in config.get("sources", []):
        if not source.get("enabled", False):
            logging.info(f"Skipping disabled source: {source['name']}")
            continue
        
        url = source.get("url")
        source_name = source.get("name")
        source_type = source.get("type")
        
        if source_type == "csv":
            output_path = os.path.join(data_dir, f"{source_name.lower().replace(' ', '_')}.csv")
        elif source_type == "json":
            output_path = os.path.join(data_dir, f"{source_name.lower().replace(' ', '_')}.json")
        else:
            logging.warning(f"Unsupported source type {source_type} for {source_name}")
            continue
        
        if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
            logging.info(f"{output_path} already exists, skipping download.")
            continue
        
        logging.info(f"Downloading {source_name} from {url}")
        if not download_file(url, output_path):
            logging.error(f"Failed to download {source_name}")

if __name__ == "__main__":
    # Example usage
    with open("config.json", "r") as f:
        config = json.load(f)
    download_datasets(config)