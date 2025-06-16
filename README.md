# RiskToNIST
## Project Overview
The project, named RiskToNIST, is a Python-based tool that:

- Downloads risk indicator datasets from public sources.
- Parses the data to extract risk indicators (e.g., CVEs, ATT&CK techniques, attack frequencies).
- Maps these indicators to NIST 800-53 controls using predefined mappings or control families.
- Normalizes and prioritizes controls based on risk scores.
- Generates outputs in JSON, CSV, and HTML formats.
- Provides a command-line interface (CLI) to execute the process.
- Identifies gaps in ATT&CK technique mappings to NIST controls for AWS workloads and prioritizes controls based on AWS mitigation data.

## Project Structure
RiskToNIST/ 
├── setup.sh # Setup script for virtual environment 
├── requirements.txt # Python dependencies 
├── run.py # Main script to run the initial risk assessment workflow 
├── data/ # Directory for downloaded datasets 
│ ├── cisa_kev.json # CISA Known Exploited Vulnerabilities JSON feed 
│ ├── nist_sp800_53_catalog.json # NIST SP 800-53 catalog in JSON format 
│ ├── attack_mapping.json # MITRE ATT&CK to NIST 800-53 mappings 
│ ├── kev_attack_mapping.json # CISA KEV to ATT&CK technique mappings 
│ ├── nvd.json # Placeholder for NVD JSON feed 
│ ├── kev.csv # Placeholder for CISA KEV catalog 
│ ├── cic_ids2017.csv # Placeholder for CIC-IDS2017 dataset 
│ └── stratosphere.csv # Placeholder for Stratosphere IPS summary 
├── mappings/ # Directory for mapping files 
│ ├── attack_to_nist.json # MITRE ATT&CK to NIST 800-53 mappings 
│ └── nist_controls.json # NIST 800-53 controls in JSON format 
├── outputs/ # Directory for generated outputs 
│ ├── output.json # Prioritized controls in JSON from initial workflow 
│ ├── output.csv # Prioritized controls in CSV from initial workflow 
│ ├── output.html # Browser-readable HTML output from initial workflow 
│ ├── aws_controls.csv # Prioritized AWS-related controls in CSV 
│ ├── aws_controls.json # Prioritized AWS-related controls in JSON 
│ ├── aws_controls_summary.html # Summary HTML report for AWS controls 
│ ├── aws_controls_details_*.html # Detailed HTML reports per AWS control 
│ └── aws_controls.zip # ZIP archive of all AWS-related HTML reports 
├── src/ # Source code directory 
│ ├── data_ingestion.py # Functions to download datasets 
│ ├── data_processing.py # Functions to parse datasets 
│ ├── risk_calculation.py # Functions to calculate control risks 
│ ├── output_generation.py # Functions to generate outputs 
│ └── env/ # Environment-specific module for AWS integration 
│ ├── main.py # Main script for AWS-focused control prioritization 
│ ├── data_loader.py # Functions to load AWS and ATT&CK-to-NIST data 
│ ├── gap_identifier.py # Functions to identify unmapped ATT&CK techniques 
│ ├── risk_prioritizer.py # Functions to prioritize controls based on AWS mitigations 
│ └── exporter.py # Functions to export AWS-related control data 
├── templates/ # HTML template directory 
│ └── controls.html # Jinja2 template for HTML output 
├── utils/ # Utility functions 
│ ├── init.py # Makes utils a package 
│ ├── download.py # Functions to download datasets 
│ ├── parse.py # Functions to parse datasets 
│ ├── map_risks.py # Functions to map risks to controls 
│ └── output.py # Functions to generate outputs 
└── config.json # Configuration file for data sources

## Getting Started
1. **Setup Environment**: Run the `setup.sh` script to set up the virtual environment and install dependencies listed in `requirements.txt`.
2. **Initial Workflow**: Execute `python run.py` to download data, process CISA KEV and NIST 800-53 controls, calculate risks, and generate outputs in the `outputs/` directory.
3. **AWS Workflow**: Run `python src/env/main.py` to load AWS mapping data, identify gaps in ATT&CK-to-NIST mappings, prioritize controls based on AWS mitigations, and generate AWS-specific outputs in the `outputs/` directory.
4. **Check Logs**: Review `run.log` for execution details and any warnings or errors.

## Features
- **Risk Assessment**: Maps CVEs to NIST 800-53 controls and calculates risk scores based on due dates and severity.
- **AWS Integration**: Analyzes AWS service mitigations for ATT&CK techniques and prioritizes NIST controls accordingly.
- **Gap Analysis**: Identifies ATT&CK techniques without NIST control mappings in AWS data.
- **Output Formats**: Generates JSON, CSV, and interactive HTML reports, including a ZIP archive for AWS-related HTML files.

## Dependencies
- `requests>=2.31.0`
- `pandas>=1.3.5`
- `plotly>=5.18.0`
- `jsonschema>=4.17.3`
- `urllib3<2.0`
- `jinja2`