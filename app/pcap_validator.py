"""
PCAP / PCAPNG Capture File Validation Module.
Verifies file existence, extension, readability, size, and TShark parsing integrity.
"""

import os
import subprocess
from typing import Tuple, Optional
from app.tshark_runner import TSharkRunner, TSharkError


class PCAPValidationError(ValueError):
    """Raised when a capture file fails integrity or format checks."""
    pass


def validate_capture_file(pcap_path: str, tshark_path: Optional[str] = None) -> Tuple[bool, str]:
    """
    Validates that the given file is an authentic, readable PCAP/PCAPNG capture.
    Returns (True, message) or raises PCAPValidationError.
    """
    if not pcap_path:
        raise PCAPValidationError("No capture file path provided.")

    if not os.path.exists(pcap_path):
        raise PCAPValidationError(f"Capture file does not exist: {pcap_path}")

    # Check extension
    valid_exts = {".pcap", ".pcapng", ".cap"}
    _, ext = os.path.splitext(pcap_path.lower())
    if ext not in valid_exts:
        raise PCAPValidationError(
            f"Invalid capture file extension '{ext}'. Only .pcap, .pcapng, and .cap files are supported."
        )

    # Check readability and size
    try:
        size = os.path.getsize(pcap_path)
        if size == 0:
            raise PCAPValidationError(f"Capture file is empty (0 bytes): {pcap_path}")
        
        with open(pcap_path, "rb") as f:
            header = f.read(128)
            if not header:
                raise PCAPValidationError("Could not read binary capture header.")
    except (IOError, OSError) as e:
        raise PCAPValidationError(f"Cannot read capture file: {e}")

    # Verify TShark can read at least the first packet or header
    runner = TSharkRunner(tshark_path=tshark_path)
    cmd = [runner.tshark_path, "-r", pcap_path, "-c", "1", "-T", "fields", "-e", "frame.number"]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if res.returncode != 0 and "The file appears to be damaged or corrupt" in res.stderr:
            raise PCAPValidationError(f"Capture validation failed: TShark reported corrupt PCAP: {res.stderr.strip()}")
    except subprocess.SubprocessError as e:
        raise PCAPValidationError(f"Failed to execute TShark validation on {pcap_path}: {e}")

    return True, f"Valid capture file ({size} bytes)"
