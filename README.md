# RiskToNIST
## Project Overview
The project, named RiskToNIST, is a Python-based tool that:

-  Downloads risk indicator datasets from public sources.
-  Parses the data to extract risk indicators (e.g., CVEs, ATT&CK techniques, attack frequencies).
-  Maps these indicators to NIST 800-53 controls using predefined mappings or control families.
-  Normalizes and prioritizes controls based on risk scores.
-  Generates outputs in JSON and HTML formats.
-  Provides a command-line interface (CLI) to execute the process.

## Project Structure
```
RiskToNIST/
├── setup.sh              # Setup script for virtual environment
├── requirements.txt      # Python dependencies
├── main.py               # Main script to run the project
├── data/                 # Directory for downloaded datasets
│   ├── nvd.json          # Placeholder for NVD JSON feed
│   ├── kev.csv           # Placeholder for CISA KEV catalog
│   ├── attack.json       # Placeholder for MITRE ATT&CK data
│   ├── cic_ids2017.csv   # Placeholder for CIC-IDS2017 dataset
│   └── stratosphere.csv  # Placeholder for Stratosphere IPS summary
├── mappings/             # Directory for mapping files
│   ├── attack_to_nist.json  # MITRE ATT&CK to NIST 800-53 mappings
│   └── nist_controls.json   # NIST 800-53 controls in JSON format
├── outputs/              # Directory for generated outputs
│   ├── controls.json     # Prioritized controls in JSON
│   └── controls.html     # Browser-readable HTML output
├── utils/                # Utility functions
│   ├── __init__.py       # Makes utils a package
│   ├── download.py       # Functions to download datasets
│   ├── parse.py          # Functions to parse datasets
│   ├── map_risks.py      # Functions to map risks to controls
│   └── output.py         # Functions to generate outputs
└── templates/            # HTML template directory
    └── controls.html     # Jinja2 template for HTML output
```
