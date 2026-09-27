# SecureMailScope — Installation & Setup Guide

This guide walks you through setting up and running **SecureMailScope** locally on Windows, Linux, or macOS.

---

## 1. System Requirements & Prerequisites

### A. Python Environment
- **Reference Baseline**: Python 3.11 (per Handbook specification)
- **Verified Runtime**: Python 3.14.7 (64-bit) tested and verified
- **Compatibility**: Any Python 3.11+ 64-bit installation
- Check installation:
  ```powershell
  python --version
  python -m pip --version
  ```

### B. System TShark / Wireshark (Mandatory System Dependency)
SecureMailScope uses **TShark** (the command-line dissector bundled with Wireshark) for passive two-pass packet extraction.

- **Windows**:
  - Download and install Wireshark from [https://www.wireshark.org/download.html](https://www.wireshark.org/download.html)
  - Ensure the "TShark" component is checked during installation.
  - Standard path: `C:\Program Files\Wireshark\tshark.exe`
  - SecureMailScope automatically discovers TShark at this location.
- **Ubuntu / Debian**:
  ```bash
  sudo apt-get update
  sudo apt-get install -y tshark
  # Select 'Yes' when asked if non-superusers should be able to capture packets
  ```
- **macOS (via Homebrew)**:
  ```bash
  brew install wireshark
  ```
- Verify TShark:
  ```bash
  tshark --version
  ```

---

## 2. Step-by-Step Installation

### Step 1: Clone the Repository
```bash
git clone https://github.com/ujjwalchaurasia63-hue/securemailscope.git
cd securemailscope
```

### Step 2: Create a Python Virtual Environment
```powershell
# Windows
python -m venv .venv
.venv\Scripts\activate

# Linux / macOS
python3 -m venv .venv
source .venv/bin/activate
```

### Step 3: Install Python Dependencies
```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### Step 4: Run Automated Environment Diagnostics
Verify that all packages and TShark are discovered properly:
```bash
python main.py --check-env
```
Expected output:
```text
Environment Diagnostics:
  • Python:          3.14.7 (or your installed 3.11+ version)
  • TShark:          AVAILABLE (TShark (Wireshark) 4.x)
  • Python Packages:
    - streamlit      AVAILABLE
    - scikit-learn   AVAILABLE
    - pandas         AVAILABLE
    - numpy          AVAILABLE
    - scapy          AVAILABLE
    - cryptography   AVAILABLE
```

### Step 5: Execute the Test Suite
Ensure all 33 unit and integration tests pass:
```bash
python -m pytest tests -v
```

---

## 3. Launching the Application

### Option A: Interactive Streamlit Web Interface (Recommended)
```bash
python -m streamlit run main.py
```
Open your browser and navigate to:
```text
http://localhost:8501
```

*(On Windows, you can also double-click `run_demo.bat` to launch automatically).*

### Option B: Standalone Headless CLI Scanner
For air-gapped terminal analysis or scripted pipelines:
```bash
# Terminal report
python main.py data/demo_mail_traffic.pcap

# Machine-readable JSON output
python main.py data/demo_mail_traffic.pcap --json data/demo_result.json
```

### Option C: Docker Container Deployment (Zero-Setup)
If you have Docker installed:
```bash
docker compose up --build
```
Open `http://localhost:8501`. TShark and all dependencies are fully provisioned inside the container.
