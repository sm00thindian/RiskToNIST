#!/bin/bash

set -e

echo "Checking for Python3..."
if ! command -v python3 &> /dev/null; then
    echo "Python3 is not installed. Please install Python3 and try again."
    exit 1
fi

echo "Checking OpenSSL version..."
PYTHON_OPENSSL_VERSION=$(python3 -c "import ssl; print(ssl.OPENSSL_VERSION)")
echo "Python is using: $PYTHON_OPENSSL_VERSION"
if [[ "$PYTHON_OPENSSL_VERSION" =~ "OpenSSL 1.0" ]]; then
    echo "Detected OpenSSL 1.0.x, ensuring urllib3<2.0 is used."
fi

echo "Creating virtual environment..."
if [ -d "venv" ]; then
    echo "Removing existing virtual environment..."
    rm -rf venv
fi
python3 -m venv venv

echo "Activating virtual environment..."
source venv/bin/activate

echo "Upgrading pip..."
pip install --upgrade pip

echo "Installing dependencies..."
pip install -r requirements.txt

echo "Running Risktonist..."
python run.py

echo "Execution completed."
