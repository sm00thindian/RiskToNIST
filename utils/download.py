import json
import requests
import os

def download_datasets(config_path="config.json"):
    """Download enabled datasets from URLs specified in the config file."""
    # Ensure data directory exists
    os.makedirs("data", exist_ok=True)
    
    with open(config_path, "r") as f:
        config = json.load(f)
    
    for source in config["sources"]:
        if source["enabled"]:
            url = source["url"]
            filename = source["name"].replace(" ", "_").lower() + ".csv"
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
            else:
                print(f"{filename} already exists, skipping download.")