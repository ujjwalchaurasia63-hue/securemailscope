@echo off
echo ======================================================================
echo           SecureMailScope - Mail Cryptographic Posture Analyzer
echo ======================================================================
echo.

python --version >nul 2>&1
if errorlevel 1 (
    echo [!] Python is not installed or not in PATH.
    echo Please install Python 3.11+ and try again.
    pause
    exit /b 1
)

echo [*] Checking environment and dependencies...
python main.py --check-env
if errorlevel 1 (
    echo.
    echo [!] Missing dependencies. Installing from requirements.txt...
    pip install -r requirements.txt
)

echo.
echo [*] Launching SecureMailScope Streamlit UI...
echo [*] Opening browser at http://localhost:8501
echo.
python -m streamlit run main.py

pause
