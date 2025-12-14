"""
APT-X Nikto Wrapper
===================

Python wrapper for Nikto web server scanner.
"""

import re
import json
from typing import Any, Dict, List, Optional

from aptx.tools.base import ToolWrapper


class NiktoWrapper(ToolWrapper):
    """
    Nikto web server scanner wrapper.

    Comprehensive web server security scanner for misconfigurations
    and vulnerabilities.
    """

    name = "nikto"
    description = "Web server vulnerability scanner"
    install_hint = "apt install nikto"
    default_timeout = 900  # 15 minutes

    def build_command(
        self,
        target: str,
        options: Optional[Dict] = None
    ) -> List[str]:
        """
        Build Nikto command.

        Options:
            port: Port to scan
            ssl: Force SSL
            plugins: Plugins to use
            tuning: Tuning options
            timeout: Request timeout
            pause: Pause between tests
            no_ssl: Disable SSL
            evasion: Evasion techniques
            extra_args: Additional arguments
        """
        options = options or {}

        cmd = [self.binary_path]

        # Target
        cmd.extend(["-h", target])

        # JSON output
        cmd.extend(["-Format", "json"])

        # Port
        if "port" in options:
            cmd.extend(["-p", str(options["port"])])

        # SSL
        if options.get("ssl", False):
            cmd.append("-ssl")
        elif options.get("no_ssl", False):
            cmd.append("-nossl")

        # Plugins
        if "plugins" in options:
            plugins = options["plugins"]
            if isinstance(plugins, list):
                plugins = ";".join(plugins)
            cmd.extend(["-Plugins", plugins])

        # Tuning (what to test)
        if "tuning" in options:
            cmd.extend(["-Tuning", options["tuning"]])

        # Timeout
        if "timeout" in options:
            cmd.extend(["-timeout", str(options["timeout"])])

        # Pause between requests
        if "pause" in options:
            cmd.extend(["-Pause", str(options["pause"])])

        # Evasion
        if "evasion" in options:
            cmd.extend(["-evasion", options["evasion"]])

        # Max time
        if "max_time" in options:
            cmd.extend(["-maxtime", str(options["max_time"])])

        # User agent
        if "user_agent" in options:
            cmd.extend(["-useragent", options["user_agent"]])

        # No interactive
        cmd.append("-nointeractive")

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
        """Parse Nikto output."""
        result = {
            "target": target,
            "findings": [],
            "server_info": {},
            "total_findings": 0,
            "osvdb_ids": [],
        }

        # Try JSON parsing first
        try:
            # Find JSON in output
            json_start = raw_output.find("{")
            json_end = raw_output.rfind("}") + 1
            if json_start >= 0 and json_end > json_start:
                json_str = raw_output[json_start:json_end]
                data = json.loads(json_str)
                return self._parse_json_output(data, target)
        except json.JSONDecodeError:
            pass

        # Fallback to text parsing
        return self._parse_text_output(raw_output, target)

    def _parse_json_output(
        self,
        data: Dict,
        target: str
    ) -> Dict[str, Any]:
        """Parse JSON format output."""
        result = {
            "target": target,
            "findings": [],
            "server_info": {},
            "total_findings": 0,
            "osvdb_ids": [],
        }

        # Parse host information
        for host in data.get("host", []):
            result["server_info"] = {
                "ip": host.get("ip", ""),
                "hostname": host.get("hostname", ""),
                "port": host.get("port", ""),
                "banner": host.get("banner", ""),
            }

            # Parse items (findings)
            for item in host.get("items", []):
                finding = {
                    "id": item.get("id", ""),
                    "osvdb": item.get("OSVDB", ""),
                    "method": item.get("method", ""),
                    "uri": item.get("uri", ""),
                    "description": item.get("description", ""),
                    "references": item.get("references", ""),
                }
                result["findings"].append(finding)

                # Track OSVDB IDs
                if finding["osvdb"]:
                    result["osvdb_ids"].append(finding["osvdb"])

        result["total_findings"] = len(result["findings"])
        return result

    def _parse_text_output(
        self,
        output: str,
        target: str
    ) -> Dict[str, Any]:
        """Parse text format output."""
        result = {
            "target": target,
            "findings": [],
            "server_info": {},
            "total_findings": 0,
            "raw_text": output[:10000],
        }

        # Extract server info
        server_match = re.search(r"Server:\s*(.+)", output)
        if server_match:
            result["server_info"]["banner"] = server_match.group(1)

        # Extract findings
        finding_pattern = r"\+\s*(OSVDB-\d+|[\w-]+):\s*([^\n]+)"
        for match in re.finditer(finding_pattern, output):
            finding = {
                "id": match.group(1),
                "description": match.group(2).strip(),
            }
            result["findings"].append(finding)

        result["total_findings"] = len(result["findings"])
        return result

    def scan(
        self,
        target: str,
        port: Optional[int] = None,
        ssl: bool = False
    ) -> "ToolResult":
        """Run web server scan."""
        options = {}
        if port:
            options["port"] = port
        if ssl:
            options["ssl"] = ssl
        return self.run(target, options=options)

    def quick_scan(self, target: str) -> "ToolResult":
        """Run a quick scan with limited tests."""
        return self.run(target, options={
            "tuning": "1234",  # Basic tests only
            "max_time": 300,  # 5 minutes max
        })

    def full_scan(self, target: str) -> "ToolResult":
        """Run comprehensive scan."""
        return self.run(target, options={
            "tuning": "x",  # All tests
        })
