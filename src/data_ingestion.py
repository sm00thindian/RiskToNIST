"""
data_ingestion.py: Handles downloading of data files for the RiskToNist project.
Downloads resources specified in config.json to the data directory.
"""

import requests
import os
import json
import logging

# Configure logging to write to download.log
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/download.log', mode='a'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def download_data(sources):
    """
    Download data files from specified sources and save them to the data directory.

    Args:
        sources (list): List of dictionaries containing source details (url, output, enabled).

    Returns:
        bool: True if all downloads succeed, False if any fail.
    """
    data_dir = 'data'
    success = True
    try:
        os.makedirs(data_dir, exist_ok=True)
        logger.debug(f"Data directory {data_dir} ensured")
    except Exception as e:
        logger.error(f"Failed to create data directory {data_dir}: {e}")
        return False

    for source in sources:
        if not source.get('enabled', False):
            logger.info(f"Skipping disabled source: {source.get('name', 'Unknown')}")
            continue
        if not all(key in source for key in ['name', 'url', 'output']):
            logger.error(f"Invalid source configuration: {source}. Missing required fields (name, url, output).")
            success = False
            continue
        url = source['url']
        output = os.path.join(data_dir, source['output'])
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            with open(output, 'wb') as f:
                f.write(response.content)
            # Validate JSON content for JSON files
            if output.endswith('.json'):
                try:
                    with open(output, 'r') as f:
                        json.load(f)
                    logger.info(f"Successfully downloaded and validated {source['name']} to {output}")
                except json.JSONDecodeError as e:
                    logger.error(f"Invalid JSON in downloaded file {output}: {e}")
                    os.remove(output)  # Remove invalid file
                    success = False
                    continue
            else:
                logger.info(f"Successfully downloaded {source['name']} to {output}")
        except requests.HTTPError as e:
            logger.error(f"HTTP error downloading {source['name']} from {url}: {e} (Status: {e.response.status_code})")
            success = False
        except requests.ConnectionError as e:
            logger.error(f"Connection error downloading {source['name']} from {url}: {e}")
            success = False
        except requests.Timeout as e:
            logger.error(f"Timeout downloading {source['name']} from {url}: {e}")
            success = False
        except requests.RequestException as e:
            logger.error(f"Failed to download {source['name']} from {url}: {e}")
            success = False
        except IOError as e:
            logger.error(f"Failed to write {source['name']} to {output}: {e}")
            success = False
    return success
