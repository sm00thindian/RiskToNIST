import json
import logging
import os
import traceback
import requests

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,  # Increase verbosity
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('outputs/run.log'),
        logging.StreamHandler()  # Add console output
    ]
)

def download_nist_catalog(data_dir):
    """Download NIST SP 800-53 catalog if not present."""
    input_path = os.path.join(data_dir, "nist_sp800_53_catalog.json")
    url = "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"
    
    if not os.path.exists(input_path):
        try:
            logging.info(f"Downloading NIST SP 800-53 catalog from {url}")
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            os.makedirs(data_dir, exist_ok=True)
            with open(input_path, "w") as f:
                json.dump(response.json(), f)
            logging.info(f"Downloaded catalog to {input_path}")
        except Exception as e:
            logging.error(f"Failed to download NIST catalog: {str(e)}\n{traceback.format_exc()}")
            raise
    else:
        logging.info(f"Using existing NIST catalog at {input_path}")
    return input_path

def generate_nist_controls(data_dir):
    """Generate nist_controls.json from the NIST SP 800-53 OSCAL catalog."""
    try:
        input_path = download_nist_catalog(data_dir)
        output_path = os.path.join(data_dir, "nist_controls.json")
        
        logging.debug(f"Checking input file: {input_path}")
        if not os.path.exists(input_path):
            raise FileNotFoundError(f"Input file {input_path} does not exist")
        
        logging.info(f"Loading NIST SP 800-53 catalog from {input_path}")
        with open(input_path, "r") as f:
            catalog = json.load(f)
        
        controls_dict = {}
        groups = catalog.get("catalog", {}).get("groups", [])
        logging.info(f"Processing {len(groups)} control families")
        
        for group in groups:
            family_title = group.get("title", "Unknown")
            controls = group.get("controls", [])
            logging.debug(f"Processing family: {family_title} with {len(controls)} controls")
            for control in controls:
                control_id = control.get("id", "").upper()
                control_title = control.get("title", control_id)
                controls_dict[control_id] = {
                    "title": control_title,
                    "family_title": family_title
                }
                subcontrols = control.get("controls", [])
                for subcontrol in subcontrols:
                    subcontrol_id = subcontrol.get("id", "").upper()
                    subcontrol_title = subcontrol.get("title", subcontrol_id)
                    controls_dict[subcontrol_id] = {
                        "title": subcontrol_title,
                        "family_title": family_title
                    }
        
        logging.debug(f"Writing {len(controls_dict)} controls to {output_path}")
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(controls_dict, f, indent=2)
        logging.info(f"Generated {len(controls_dict)} controls in {output_path}")
    
    except Exception as e:
        logging.error(f"Failed to generate nist_controls.json: {str(e)}\n{traceback.format_exc()}")
        raise

if __name__ == "__main__":
    logging.debug("Starting generate_nist_controls.py")
    generate_nist_controls("data")
