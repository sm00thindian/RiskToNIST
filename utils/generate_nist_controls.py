import json
import logging
import os

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def generate_nist_controls(data_dir):
    """Generate nist_controls.json from the NIST SP 800-53 OSCAL catalog.

    Args:
        data_dir (str): Directory containing data files.
    """
    input_path = os.path.join(data_dir, "nist_sp800_53_catalog.json")
    output_path = os.path.join(data_dir, "nist_controls.json")
    
    try:
        # Load the OSCAL catalog
        if not os.path.exists(input_path):
            logging.error(f"NIST SP 800-53 catalog not found at {input_path}")
            return
        with open(input_path, "r") as f:
            catalog = json.load(f)
        logging.info(f"Loaded NIST SP 800-53 catalog from {input_path}")

        # Initialize controls dictionary
        controls_dict = {}

        # Process groups (families) and their controls
        groups = catalog.get("catalog", {}).get("groups", [])
        for group in groups:
            family_title = group.get("title", "Unknown")
            for control in group.get("controls", []):
                control_id = control.get("id", "").upper()  # Normalize to upper case (e.g., ac-1)
                control_title = control.get("title", control_id)
                controls_dict[control_id] = {
                    "title": control_title,
                    "family_title": family_title
                }
                # Process control enhancements (subcontrols)
                for subcontrol in control.get("controls", []):
                    subcontrol_id = subcontrol.get("id", "").upper()
                    subcontrol_title = subcontrol.get("title", subcontrol_id)
                    controls_dict[subcontrol_id] = {
                        "title": subcontrol_title,
                        "family_title": family_title
                    }

        # Save to nist_controls.json
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(controls_dict, f, indent=2)
        logging.info(f"Generated {len(controls_dict)} controls in {output_path}")
    
    except Exception as e:
        logging.error(f"Failed to generate nist_controls.json: {e}")

if __name__ == "__main__":
    generate_nist_controls("data")
