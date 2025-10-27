"""
data_ingestion.py: Handles downloading of data files for the RiskToNist project.
Downloads resources specified in config.json to the data directory.
"""

import requests
import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def download_data(sources):
    """
    Download data files from specified sources and save them to the data directory.

    Args:
        sources (list): List of dictionaries containing source details (url, output, enabled).

    Returns:
        None

    Raises:
        requests.RequestException: If a download fails due to network or HTTP errors.
    """
    data_dir = 'data'
    try:
        os.makedirs(data_dir, exist_ok=True)
        logger.debug(f"Data directory {data_dir} ensured")
    except Exception as e:
        logger.error(f"Failed to create data directory {data_dir}: {e}")
        raise

    for source in sources:
        if not source.get('enabled', False):
            logger.info(f"Skipping disabled source: {source.get('name', 'Unknown')}")
            continue
        if not all(key in source for key in ['name', 'url', 'output']):
            logger.error(f"Invalid source configuration: {source}. Missing required fields (name, url, output).")
            continue
        url = source['url']
        output = os.path.join(data_dir, source['output'])
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            with open(output, 'wb') as f:
                f.write(response.content)
            logger.info(f"Successfully downloaded {source['name']} to {output}")
        except requests.RequestException as e:
            logger.error(f"Failed to download {source['name']} from {url}: {e}")
            raise
        except IOError as e:
            logger.error(f"Failed to write {source['name']} to {output}: {e}")
            raise
