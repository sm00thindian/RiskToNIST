@echo off
REM setup.bat: Script to fully set up the RiskToNIST project, download datasets, and generate outputs on Windows

REM Exit on any error (similar to set -e in Bash)
setlocal EnableDelayedExpansion

REM Function to check if a command exists
where python >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo Error: Python is not installed. Please install Python 3 from https://www.python.org/downloads/ and ensure it's in your PATH.
    exit /b 1
)

REM Check for unzip (not always pre-installed on Windows)
where unzip >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo Error: unzip is not installed. Please install it (e.g., via Chocolatey: 'choco install unzip' or download from http://gnuwin32.sourceforge.net/packages/unzip.htm).
    exit /b 1
)

REM Create virtual environment if it doesn't exist
echo Setting up virtual environment...
if not exist "venv" (
    python -m venv venv
) else (
    echo Virtual environment already exists, skipping creation.
)

REM Activate virtual environment
echo Activating virtual environment...
call venv\Scripts\activate
if %ERRORLEVEL% neq 0 (
    echo Error: Failed to activate virtual environment.
    exit /b 1
)

REM Upgrade pip and install dependencies
echo Installing Python dependencies...
pip install --upgrade pip --quiet --trusted-host pypi.org --trusted-host files.pythonhosted.org
if exist "requirements.txt" (
    pip install -r requirements.txt --quiet --trusted-host pypi.org --trusted-host files.pythonhosted.org
) else (
    echo Error: requirements.txt not found.
    exit /b 1
)

REM Create required directories
echo Creating directory structure...
mkdir data mappings outputs templates 2>nul

REM Verify main.py exists
if not exist "main.py" (
    echo Error: main.py not found in the project root.
    exit /b 1
)

REM Download datasets and generate outputs
echo Running the RiskToNIST project to download datasets and generate outputs...
python main.py
if %ERRORLEVEL% neq 0 (
    echo Error: Failed to run main.py. Check logs above for errors.
    exit /b 1
)

REM Check if outputs were generated
if exist "outputs\controls.json" (
    if exist "outputs\controls.html" (
        echo Outputs successfully generated in 'outputs\' directory:
        echo - JSON output: outputs\controls.json
        echo - HTML output: outputs\controls.html (open in a browser)
    ) else (
        echo Error: Failed to generate outputs. Missing outputs\controls.html.
        exit /b 1
    )
) else (
    echo Error: Failed to generate outputs. Missing outputs\controls.json.
    exit /b 1
)

echo Setup complete! To work in the virtual environment, run:
echo venv\Scripts\activate
echo To re-run the project, use: python main.py

endlocal
