"""
APT-X httpx Wrapper
===================

Python wrapper for ProjectDiscovery httpx HTTP toolkit.
"""

import json
from typing import Any, Dict, List, Optional

from aptx.tools.base import ToolWrapper


class HttpxWrapper(ToolWrapper):
    """
    httpx HTTP toolkit wrapper.

    Fast and multi-purpose HTTP toolkit for web probing and analysis.
    """

    name = "httpx"
    description = "HTTP web server probing and technology detection"
    install_hint = "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
    default_timeout = 300  # 5 minutes

    def build_command(
        self,
        target: str,
        options: Optional[Dict] = None
    ) -> List[str]:
        """
        Build httpx command.

        Options:
            targets: List of targets (alternative to single target)
            status_code: Include status code
            content_length: Include content length
            title: Include page title
            web_server: Include web server
            tech_detect: Enable technology detection
            follow_redirects: Follow redirects
            threads: Number of threads
            timeout: Request timeout
            ports: Ports to probe
            extra_args: Additional arguments
        """
        options = options or {}

        cmd = [self.binary_path]

        # JSON output
        cmd.extend(["-json", "-silent"])

        # Probe options (enable useful info by default)
        cmd.append("-status-code")
        cmd.append("-content-length")
        cmd.append("-title")
        cmd.append("-web-server")
        cmd.append("-content-type")

        # Tech detection
        if options.get("tech_detect", True):
            cmd.append("-tech-detect")

        # Follow redirects
        if options.get("follow_redirects", True):
            cmd.extend(["-follow-redirects", "-follow-host-redirects"])

        # Max redirects
        cmd.extend(["-max-redirects", str(options.get("max_redirects", 5))])

        # Threads
        if "threads" in options:
            cmd.extend(["-threads", str(options["threads"])])

        # Timeout
        if "timeout" in options:
            cmd.extend(["-timeout", str(options["timeout"])])

        # Rate limit
        if "rate_limit" in options:
            cmd.extend(["-rate-limit", str(options["rate_limit"])])

        # Ports
        if "ports" in options:
            ports = options["ports"]
            if isinstance(ports, list):
                ports = ",".join(map(str, ports))
            cmd.extend(["-ports", ports])

        # Extra arguments
        if "extra_args" in options:
            extra = options["extra_args"]
            if isinstance(extra, str):
                cmd.extend(extra.split())
            elif isinstance(extra, list):
                cmd.extend(extra)

        # Target handling
        if "targets" in options and isinstance(options["targets"], list):
            # Multiple targets via stdin - would need different handling
            cmd.extend(["-u", target])
        else:
            cmd.extend(["-u", target])

        return cmd

    def parse_output(
        self,
        raw_output: str,
        target: str
    ) -> Dict[str, Any]:
        """Parse httpx JSON output."""
        result = {
            "target": target,
            "urls": [],
            "web_servers": [],
            "technologies": [],
            "status_codes": {},
            "total_urls": 0,
        }

        seen_urls = set()

        # Parse JSONL output
        for line in raw_output.strip().split("\n"):
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            url = data.get("url", "")
            if not url or url in seen_urls:
                continue

            seen_urls.add(url)

            url_info = {
                "url": url,
                "input": data.get("input", ""),
                "status_code": data.get("status_code"),
                "content_length": data.get("content_length"),
                "content_type": data.get("content_type"),
                "title": data.get("title", ""),
                "web_server": data.get("webserver", ""),
                "technologies": data.get("tech", []),
                "final_url": data.get("final_url", url),
                "host": data.get("host", ""),
                "port": data.get("port"),
                "scheme": data.get("scheme", ""),
                "method": data.get("method", "GET"),
                "response_time": data.get("response_time", ""),
            }

            result["urls"].append(url_info)

            # Track status codes
            status = str(data.get("status_code", "unknown"))
            result["status_codes"][status] = result["status_codes"].get(status, 0) + 1

            # Track web servers
            webserver = data.get("webserver", "")
            if webserver and webserver not in result["web_servers"]:
                result["web_servers"].append(webserver)

            # Track technologies
            for tech in data.get("tech", []):
                if tech not in result["technologies"]:
                    result["technologies"].append(tech)

        result["total_urls"] = len(result["urls"])

        return result

    def probe(
        self,
        target: str,
        ports: Optional[List[int]] = None,
        tech_detect: bool = True
    ) -> "ToolResult":
        """Probe a target for HTTP servers."""
        options = {
            "tech_detect": tech_detect,
            "follow_redirects": True,
        }
        if ports:
            options["ports"] = ports
        return self.run(target, options=options)

    def probe_multiple(
        self,
        targets: List[str],
        **kwargs
    ) -> List["ToolResult"]:
        """Probe multiple targets."""
        results = []
        for target in targets:
            results.append(self.probe(target, **kwargs))
        return results
