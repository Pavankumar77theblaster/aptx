"""
APT-X Nmap Wrapper
==================

Python wrapper for Nmap network scanner with structured output parsing.
"""

import re
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional
from dataclasses import dataclass

from aptx.tools.base import ToolWrapper, ToolResult


@dataclass
class NmapHost:
    """Parsed Nmap host result."""
    ip: str
    hostname: Optional[str]
    state: str
    ports: List[Dict]
    os_matches: List[Dict]
    scripts: List[Dict]


class NmapWrapper(ToolWrapper):
    """
    Nmap network scanner wrapper.

    Supports various scan types with XML output parsing
    for structured data extraction.
    """

    name = "nmap"
    description = "Network port scanner and service detection"
    install_hint = "apt install nmap"
    default_timeout = 600  # 10 minutes

    # Scan type presets
    SCAN_TYPES = {
        "quick": "-sT -T4 --top-ports 100",
        "default": "-sT -sV -T4 --top-ports 1000",
        "full": "-sT -sV -sC -T4 -p-",
        "stealth": "-sS -T2 -p-",
        "udp": "-sU -T4 --top-ports 100",
        "version": "-sV -T4",
        "vuln": "-sV --script vuln",
        "safe": "-sT -T3 --top-ports 1000",  # Non-aggressive
    }

    def build_command(
        self,
        target: str,
        options: Optional[Dict] = None
    ) -> List[str]:
        """
        Build Nmap command.

        Options:
            scan_type: Preset scan type (quick, default, full, stealth, etc.)
            ports: Port specification (e.g., "22,80,443" or "1-1000")
            scripts: NSE scripts to run
            timing: Timing template (0-5)
            extra_args: Additional arguments
        """
        options = options or {}

        cmd = [self.binary_path]

        # XML output
        cmd.extend(["-oX", "-"])

        # Scan type preset
        scan_type = options.get("scan_type", "safe")
        if scan_type in self.SCAN_TYPES:
            cmd.extend(self.SCAN_TYPES[scan_type].split())

        # Custom ports
        if "ports" in options:
            cmd.extend(["-p", options["ports"]])

        # Scripts
        if "scripts" in options:
            scripts = options["scripts"]
            if isinstance(scripts, list):
                scripts = ",".join(scripts)
            cmd.extend(["--script", scripts])

        # Timing
        if "timing" in options:
            cmd.append(f"-T{options['timing']}")

        # Service version detection
        if options.get("version_detection", True):
            if "-sV" not in cmd:
                cmd.append("-sV")

        # OS detection (requires root)
        if options.get("os_detection", False):
            cmd.append("-O")

        # Extra arguments
        if "extra_args" in options:
            extra = options["extra_args"]
            if isinstance(extra, str):
                cmd.extend(extra.split())
            elif isinstance(extra, list):
                cmd.extend(extra)

        # Target
        cmd.append(target)

        return cmd

    def parse_output(
        self,
        raw_output: str,
        target: str
    ) -> Dict[str, Any]:
        """Parse Nmap XML output into structured data."""
        result = {
            "target": target,
            "hosts": [],
            "total_hosts": 0,
            "hosts_up": 0,
            "total_ports": 0,
            "open_ports": 0,
            "services": [],
            "scan_info": {}
        }

        try:
            root = ET.fromstring(raw_output)
        except ET.ParseError:
            # Try to extract data from text output
            return self._parse_text_output(raw_output, target)

        # Parse scan info
        scaninfo = root.find("scaninfo")
        if scaninfo is not None:
            result["scan_info"] = {
                "type": scaninfo.get("type"),
                "protocol": scaninfo.get("protocol"),
                "services": scaninfo.get("services"),
            }

        # Parse hosts
        for host_elem in root.findall("host"):
            host_data = self._parse_host(host_elem)
            if host_data:
                result["hosts"].append(host_data)
                if host_data["state"] == "up":
                    result["hosts_up"] += 1

                # Count ports
                for port in host_data.get("ports", []):
                    result["total_ports"] += 1
                    if port.get("state") == "open":
                        result["open_ports"] += 1
                        # Track services
                        if port.get("service"):
                            result["services"].append({
                                "host": host_data["ip"],
                                "port": port["port"],
                                "protocol": port["protocol"],
                                "service": port["service"],
                                "version": port.get("version", "")
                            })

        result["total_hosts"] = len(result["hosts"])

        return result

    def _parse_host(self, host_elem: ET.Element) -> Optional[Dict]:
        """Parse a single host element."""
        # Get state
        status = host_elem.find("status")
        state = status.get("state") if status is not None else "unknown"

        # Get address
        address = None
        hostname = None

        for addr in host_elem.findall("address"):
            if addr.get("addrtype") == "ipv4":
                address = addr.get("addr")
                break
            elif addr.get("addrtype") == "ipv6":
                address = addr.get("addr")

        if not address:
            return None

        # Get hostname
        hostnames = host_elem.find("hostnames")
        if hostnames is not None:
            hostname_elem = hostnames.find("hostname")
            if hostname_elem is not None:
                hostname = hostname_elem.get("name")

        # Parse ports
        ports = []
        ports_elem = host_elem.find("ports")
        if ports_elem is not None:
            for port_elem in ports_elem.findall("port"):
                port_data = self._parse_port(port_elem)
                if port_data:
                    ports.append(port_data)

        # Parse OS matches
        os_matches = []
        os_elem = host_elem.find("os")
        if os_elem is not None:
            for osmatch in os_elem.findall("osmatch"):
                os_matches.append({
                    "name": osmatch.get("name"),
                    "accuracy": osmatch.get("accuracy"),
                })

        # Parse host scripts
        scripts = []
        hostscript = host_elem.find("hostscript")
        if hostscript is not None:
            for script in hostscript.findall("script"):
                scripts.append({
                    "id": script.get("id"),
                    "output": script.get("output", "")[:1000]
                })

        return {
            "ip": address,
            "hostname": hostname,
            "state": state,
            "ports": ports,
            "os_matches": os_matches,
            "scripts": scripts,
        }

    def _parse_port(self, port_elem: ET.Element) -> Optional[Dict]:
        """Parse a single port element."""
        port_id = port_elem.get("portid")
        protocol = port_elem.get("protocol")

        state_elem = port_elem.find("state")
        state = state_elem.get("state") if state_elem is not None else "unknown"
        reason = state_elem.get("reason") if state_elem is not None else ""

        # Service info
        service_elem = port_elem.find("service")
        service = None
        version = None
        product = None

        if service_elem is not None:
            service = service_elem.get("name")
            product = service_elem.get("product")
            version = service_elem.get("version")

            # Build version string
            version_parts = []
            if product:
                version_parts.append(product)
            if version:
                version_parts.append(version)
            version = " ".join(version_parts) if version_parts else None

        # Port scripts
        scripts = []
        for script in port_elem.findall("script"):
            scripts.append({
                "id": script.get("id"),
                "output": script.get("output", "")[:1000]
            })

        return {
            "port": int(port_id) if port_id else 0,
            "protocol": protocol,
            "state": state,
            "reason": reason,
            "service": service,
            "version": version,
            "scripts": scripts,
        }

    def _parse_text_output(
        self,
        output: str,
        target: str
    ) -> Dict[str, Any]:
        """Fallback parser for text output."""
        result = {
            "target": target,
            "hosts": [],
            "raw_text": output[:10000]
        }

        # Extract open ports from text
        port_pattern = r"(\d+)/(tcp|udp)\s+open\s+(\S+)"
        ports = []
        for match in re.finditer(port_pattern, output):
            ports.append({
                "port": int(match.group(1)),
                "protocol": match.group(2),
                "state": "open",
                "service": match.group(3)
            })

        if ports:
            result["hosts"].append({
                "ip": target,
                "hostname": None,
                "state": "up",
                "ports": ports
            })

        return result

    def quick_scan(self, target: str) -> ToolResult:
        """Run a quick top-100 ports scan."""
        return self.run(target, options={"scan_type": "quick"})

    def full_scan(self, target: str) -> ToolResult:
        """Run a full port scan with version detection."""
        return self.run(target, options={"scan_type": "full"})

    def vuln_scan(self, target: str) -> ToolResult:
        """Run vulnerability scanning scripts."""
        return self.run(target, options={"scan_type": "vuln"})

    def safe_scan(self, target: str, ports: str = "1-1000") -> ToolResult:
        """Run a non-aggressive safe scan."""
        return self.run(target, options={
            "scan_type": "safe",
            "ports": ports
        })
