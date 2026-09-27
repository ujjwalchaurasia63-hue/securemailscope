"""
Environment and Dependency Validation for SecureMailScope.
Checks Python version, required packages, and system TShark binary.
"""

import os
import sys
import shutil
import subprocess
from typing import Dict, Any, List, Tuple

# Ensure parent directory is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass


REQUIRED_PACKAGES = [
    ("streamlit", "streamlit"),
    ("scikit-learn", "sklearn"),
    ("pandas", "pandas"),
    ("numpy", "numpy"),
    ("scapy", "scapy"),
    ("cryptography", "cryptography")
]


def check_environment() -> Dict[str, Any]:
    """
    Validates Python environment, installed dependencies, and TShark binary.
    Returns structured environment status report.
    """
    py_version = sys.version.split()[0]
    
    # Check packages
    package_status: Dict[str, Dict[str, Any]] = {}
    missing_packages: List[str] = []
    for pkg_name, import_name in REQUIRED_PACKAGES:
        try:
            mod = __import__(import_name)
            ver = getattr(mod, "__version__", "installed")
            package_status[pkg_name] = {"available": True, "version": ver}
        except ImportError:
            package_status[pkg_name] = {"available": False, "version": None}
            missing_packages.append(pkg_name)

    # Check TShark
    from app.tshark_runner import TSharkRunner, TSharkError
    tshark_info: Dict[str, Any] = {"available": False, "path": None, "version": None, "error": None}
    try:
        runner = TSharkRunner()
        tshark_info["available"] = True
        tshark_info["path"] = runner.tshark_path
        tshark_info["version"] = runner.get_version()
    except TSharkError as e:
        tshark_info["error"] = str(e)

    all_ok = (len(missing_packages) == 0 and tshark_info["available"])

    return {
        "all_valid": all_ok,
        "python_version": py_version,
        "packages": package_status,
        "missing_packages": missing_packages,
        "tshark": tshark_info
    }


def format_env_report(status: Dict[str, Any]) -> str:
    """Formats environment status for terminal display."""
    lines = []
    lines.append("Environment Diagnostics:")
    lines.append(f"  • Python:          {status['python_version']}")
    
    tshark = status["tshark"]
    if tshark["available"]:
        lines.append(f"  • TShark:          AVAILABLE ({tshark['version']})")
        lines.append(f"    Path:            {tshark['path']}")
    else:
        lines.append(f"  • TShark:          MISSING — {tshark['error']}")

    lines.append("  • Python Packages:")
    for pkg, info in status["packages"].items():
        state = f"AVAILABLE ({info['version']})" if info["available"] else "MISSING"
        lines.append(f"    - {pkg:<14} {state}")

    return "\n".join(lines)


if __name__ == "__main__":
    status = check_environment()
    print(format_env_report(status))
