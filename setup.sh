#!/bin/bash

set -e

echo "Checking for Python3..."
if ! command -v python3 &> /dev/null; then
    echo "Python3 is not installed. Please install Python3 and try again."
    exit 1
fi

echo "Creating virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi

echo "Activating virtual environment..."
source venv/bin/activate

echo "Installing dependencies..."
pip install -r requirements.txt

if [ ! -f "satisfied_controls.txt" ]; then
    echo "satisfied_controls.txt not found. Please create this file with the list of satisfied NIST controls."
    exit 1
fi

echo "Running Risktonist..."
python run.py

echo "Execution completed."
