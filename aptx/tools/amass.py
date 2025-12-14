"""
APT-X Amass Wrapper
===================

Python wrapper for OWASP Amass subdomain enumeration tool.
"""

import json
from typing import Any, Dict, List, Optional

from aptx.tools.base import ToolWrapper


class AmassWrapper(ToolWrapper):
    """
    OWASP Amass subdomain enumeration wrapper.

    Supports passive and active enumeration modes with
    structured JSON output.
    """

    name = "amass"
    description = "In-depth subdomain enumeration"
    install_hint = "apt install amass"
    default_timeout = 600  # 10 minutes

    # Enumeration modes
    MODES = {
        "passive": "enum -passive",
        "active": "enum -active",
        "intel": "intel",
    }

    def build_command(
        self,
        target: str,
        options: Optional[Dict] = None
    ) -> List[str]:
        """
        Build Amass command.

        Options:
            mode: Enumeration mode (passive, active, intel)
            timeout: Timeout in minutes
            max_dns: Maximum DNS queries
            config: Config file path
            extra_args: Additional arguments
        """
        options = options or {}

        cmd = [self.binary_path]

        # Mode
        mode = options.get("mode", "passive")
        if mode in self.MODES:
            cmd.extend(self.MODES[mode].split())
        else:
            cmd.extend(["enum", "-passive"])

        # JSON output
        cmd.extend(["-json", "-"])

        # Domain
        cmd.extend(["-d", target])

        # Timeout
        if "timeout" in options:
            cmd.extend(["-timeout", str(options["timeout"])])

        # Max DNS queries
        if "max_dns" in options:
            cmd.extend(["-max-dns-queries", str(options["max_dns"])])

        # Config file
        if "config" in options:
            cmd.extend(["-config", options["config"]])

        # Brute force
        if options.get("brute", False):
            cmd.append("-brute")

        # Extra arguments
        if "extra_args" in options:
            extra = options["extra_args"]
            if isinstance(extra, str):
                cmd.extend(extra.split())
            elif isinstance(extra, list):
                cmd.extend(extra)

        return cmd

    def parse_output(
        self,
        raw_output: str,
        target: str
    ) -> Dict[str, Any]:
        """Parse Amass JSON output."""
        result = {
            "target": target,
            "subdomains": [],
            "addresses": [],
            "sources": {},
            "asns": [],
            "total_subdomains": 0,
        }

        seen_subdomains = set()

        # Parse JSONL output
        for line in raw_output.strip().split("\n"):
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            # Extract subdomain
            name = data.get("name", "")
            if name and name not in seen_subdomains:
                seen_subdomains.add(name)

                subdomain_info = {
                    "subdomain": name,
                    "addresses": data.get("addresses", []),
                    "sources": data.get("sources", []),
                    "tag": data.get("tag", ""),
                }

                result["subdomains"].append(subdomain_info)

                # Track sources
                for source in data.get("sources", []):
                    result["sources"][source] = result["sources"].get(source, 0) + 1

                # Track addresses
                for addr in data.get("addresses", []):
                    if addr not in result["addresses"]:
                        result["addresses"].append(addr)

                # Track ASNs
                if "asn" in data:
                    asn_info = {
                        "asn": data["asn"],
                        "description": data.get("asn_description", "")
                    }
                    if asn_info not in result["asns"]:
                        result["asns"].append(asn_info)

        result["total_subdomains"] = len(result["subdomains"])
        result["total_addresses"] = len(result["addresses"])

        return result

    def passive_enum(self, domain: str) -> "ToolResult":
        """Run passive subdomain enumeration."""
        return self.run(domain, options={"mode": "passive"})

    def active_enum(self, domain: str) -> "ToolResult":
        """Run active subdomain enumeration."""
        return self.run(domain, options={"mode": "active"})

    def intel(self, domain: str) -> "ToolResult":
        """Run intelligence gathering mode."""
        return self.run(domain, options={"mode": "intel"})
