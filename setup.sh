#!/bin/bash
# setup.sh: Script to create a virtual environment and install dependencies

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Upgrade pip and install dependencies
pip install --upgrade pip
pip install -r requirements.txt

echo "Virtual environment setup complete. Activate it with 'source venv/bin/activate'."
