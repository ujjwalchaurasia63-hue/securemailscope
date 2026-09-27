# SecureMailScope — Deployment Guide

This guide covers deploying SecureMailScope locally on bare metal, inside Docker containers, and on cloud hosting platforms.

---

## 1. System Requirements

### Hardware
- **CPU**: Dual-core x86_64 or ARM64 processor (quad-core recommended for multi-megabyte PCAPs).
- **RAM**: Minimum 2 GB (4 GB recommended).
- **Disk**: 500 MB free space for code, dependencies, and temporary stream reassembly.

### Software Prerequisites
- **Python**: Reference baseline Python 3.11 (tested compatible with Python 3.11 through 3.14.7).
- **TShark**: Wireshark 3.4+ or 4.x command-line engine (`tshark` in system PATH).

---

## 2. Local Deployment (Windows / Linux / macOS)

### Step 1: Clone Repository
```bash
git clone https://github.com/ujjwalchaurasia63-hue/securemailscope.git
cd securemailscope
```

### Step 2: Set Up Python Virtual Environment
```bash
# Windows
python -m venv .venv
.\.venv\Scripts\activate

# Linux / macOS
python3 -m venv .venv
source .venv/bin/activate
```

### Step 3: Install Python Dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 4: Verify Environment Health
```bash
python main.py --check-env
```
Ensure output confirms:
- Python version $\ge 3.11$
- TShark installed and reachable
- Scapy, Cryptography, Scikit-learn, and Streamlit available

### Step 5: Launch the Application
```bash
# Standard Launch
python -m streamlit run main.py

# Or CLI Flag
python main.py --ui

# One-Click Scripts
# Windows:
.\run_demo.bat
# Linux/macOS:
chmod +x ./run_demo.sh
./run_demo.sh
```
Open your browser to `http://localhost:8501`.

---

## 3. Docker Deployment

SecureMailScope includes a containerized environment with TShark pre-installed on Debian 12 (Bookworm).

### Option A: Using Docker Compose (Recommended)
```bash
# Start container in background
docker compose up -d

# View application logs
docker compose logs -f

# Stop container
docker compose down
```
Access the application at `http://localhost:8501`. The `./data` directory is mounted into `/app/data` for PCAP sharing.

### Option B: Using Standalone Docker CLI
```bash
# Build Docker image
docker build -t securemailscope:latest .

# Run container with volume mount
docker run -d \
  --name securemailscope \
  -p 8501:8501 \
  -v "$(pwd)/data:/app/data" \
  securemailscope:latest
```

### Container Health Check
The Dockerfile configures an automated container healthcheck:
```bash
docker inspect --format='{{json .State.Health}}' securemailscope
```
Health endpoint queried: `http://localhost:8501/_stcore/health`.

---

## 4. Streamlit Community Cloud Deployment

SecureMailScope includes native support for Streamlit Community Cloud:

1. **System Packages**: `packages.txt` in the root repository specifies:
   ```text
   tshark
   ```
   Streamlit Cloud installs TShark via `apt-get` automatically during build.
2. **Python Dependencies**: `requirements.txt` specifies all required libraries with pinned versions.
3. **Entry Point**: Set the main file path to `main.py`.

---

## 5. Air-Gapped & Offline Deployment

For classified or isolated SOC / forensics networks:

1. On an internet-connected staging machine:
   ```bash
   pip download -r requirements.txt -d ./wheels
   ```
2. Transfer `./wheels` and the project directory via authorized optical media or encrypted drive.
3. On the air-gapped machine:
   ```bash
   pip install --no-index --find-links=./wheels -r requirements.txt
   ```
4. Verify TShark is pre-installed via system package manager or offline MSI installer.
5. Launch SecureMailScope without any outbound internet access.
