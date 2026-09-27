#!/usr/bin/env bash
set -e

echo "======================================================================"
echo "          SecureMailScope - Mail Cryptographic Posture Analyzer"
echo "======================================================================"
echo ""

if ! command -v python3 &> /dev/null; then
    echo "[!] python3 could not be found. Please install Python 3.11+."
    exit 1
fi

echo "[*] Checking environment diagnostics..."
python3 main.py --check-env || {
    echo "[*] Installing dependencies..."
    pip install -r requirements.txt
}

echo ""
echo "[*] Launching SecureMailScope Streamlit UI at http://localhost:8501..."
python3 -m streamlit run main.py
