#!/usr/bin/env python3
"""
APT-X Tool Checker
==================

Checks availability and versions of required external tools.
"""

import shutil
import subprocess
import sys
from typing import Dict, List, Optional, Tuple


# Tool definitions
TOOLS = {
    "nmap": {
        "description": "Network scanner",
        "required": True,
        "version_cmd": ["nmap", "--version"],
        "install": "apt install nmap",
    },
    "amass": {
        "description": "Subdomain enumeration",
        "required": False,
        "version_cmd": ["amass", "-version"],
        "install": "go install github.com/owasp-amass/amass/v4/...@master",
    },
    "subfinder": {
        "description": "Subdomain discovery",
        "required": False,
        "version_cmd": ["subfinder", "-version"],
        "install": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    },
    "httpx": {
        "description": "HTTP probing",
        "required": False,
        "version_cmd": ["httpx", "-version"],
        "install": "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
    },
    "nuclei": {
        "description": "Vulnerability scanner",
        "required": False,
        "version_cmd": ["nuclei", "-version"],
        "install": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    },
    "ffuf": {
        "description": "Web fuzzer",
        "required": False,
        "version_cmd": ["ffuf", "-V"],
        "install": "go install github.com/ffuf/ffuf/v2@latest",
    },
    "nikto": {
        "description": "Web server scanner",
        "required": False,
        "version_cmd": ["nikto", "-Version"],
        "install": "apt install nikto",
    },
    "sqlmap": {
        "description": "SQL injection tool",
        "required": False,
        "version_cmd": ["sqlmap", "--version"],
        "install": "apt install sqlmap",
    },
}


def check_tool(name: str) -> Tuple[bool, Optional[str]]:
    """
    Check if a tool is available and get its version.

    Returns:
        Tuple of (is_available, version_string)
    """
    tool = TOOLS.get(name, {})

    # Check if binary exists
    binary = shutil.which(name)
    if not binary:
        return False, None

    # Get version
    version_cmd = tool.get("version_cmd", [name, "--version"])
    try:
        result = subprocess.run(
            version_cmd,
            capture_output=True,
            text=True,
            timeout=10
        )
        version = result.stdout.strip() or result.stderr.strip()
        # Extract first line
        version = version.split("\n")[0][:50]
        return True, version
    except Exception:
        return True, "unknown version"


def check_all_tools() -> Dict[str, Dict]:
    """Check all tools and return status."""
    results = {}

    for name, info in TOOLS.items():
        available, version = check_tool(name)
        results[name] = {
            "available": available,
            "version": version,
            "description": info["description"],
            "required": info["required"],
            "install": info["install"],
        }

    return results


def print_status():
    """Print tool status in formatted output."""
    print("\n" + "=" * 60)
    print("APT-X Tool Status Check")
    print("=" * 60 + "\n")

    results = check_all_tools()

    available_count = 0
    required_missing = []
    optional_missing = []

    for name, status in results.items():
        if status["available"]:
            available_count += 1
            mark = "\033[92m✓\033[0m"  # Green checkmark
            version = f" ({status['version']})" if status["version"] else ""
            print(f"  {mark} {name:12} - {status['description']}{version}")
        else:
            mark = "\033[91m✗\033[0m"  # Red X
            req = "[REQUIRED]" if status["required"] else "[optional]"
            print(f"  {mark} {name:12} - {status['description']} {req}")

            if status["required"]:
                required_missing.append(name)
            else:
                optional_missing.append(name)

    print("\n" + "-" * 60)
    print(f"Available: {available_count}/{len(TOOLS)}")

    if required_missing:
        print(f"\n\033[91mMissing required tools:\033[0m")
        for name in required_missing:
            print(f"  - {name}: {TOOLS[name]['install']}")

    if optional_missing:
        print(f"\n\033[93mMissing optional tools:\033[0m")
        for name in optional_missing:
            print(f"  - {name}: {TOOLS[name]['install']}")

    print()

    return len(required_missing) == 0


def main():
    """Main entry point."""
    success = print_status()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
