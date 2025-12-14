"""
APT-X Subfinder Wrapper
=======================

Python wrapper for ProjectDiscovery Subfinder subdomain enumeration tool.
"""

import json
from typing import Any, Dict, List, Optional

from aptx.tools.base import ToolWrapper


class SubfinderWrapper(ToolWrapper):
    """
    Subfinder subdomain enumeration wrapper.

    Fast passive subdomain discovery tool from ProjectDiscovery.
    """

    name = "subfinder"
    description = "Fast passive subdomain enumeration"
    install_hint = "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    default_timeout = 300  # 5 minutes

    def build_command(
        self,
        target: str,
        options: Optional[Dict] = None
    ) -> List[str]:
        """
        Build Subfinder command.

        Options:
            sources: List of sources to use
            exclude_sources: Sources to exclude
            all_sources: Use all available sources
            recursive: Enable recursive enumeration
            timeout: Timeout in seconds
            threads: Number of threads
            max_time: Maximum time in minutes
            extra_args: Additional arguments
        """
        options = options or {}

        cmd = [self.binary_path]

        # Domain
        cmd.extend(["-d", target])

        # JSON output
        cmd.extend(["-oJ", "-silent"])

        # Sources
        if "sources" in options:
            sources = options["sources"]
            if isinstance(sources, list):
                sources = ",".join(sources)
            cmd.extend(["-sources", sources])

        # Exclude sources
        if "exclude_sources" in options:
            exclude = options["exclude_sources"]
            if isinstance(exclude, list):
                exclude = ",".join(exclude)
            cmd.extend(["-es", exclude])

        # All sources
        if options.get("all_sources", False):
            cmd.append("-all")

        # Recursive
        if options.get("recursive", False):
            cmd.append("-recursive")

        # Threads
        if "threads" in options:
            cmd.extend(["-t", str(options["threads"])])

        # Timeout
        if "timeout" in options:
            cmd.extend(["-timeout", str(options["timeout"])])

        # Max time
        if "max_time" in options:
            cmd.extend(["-max-time", str(options["max_time"])])

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
        """Parse Subfinder JSON output."""
        result = {
            "target": target,
            "subdomains": [],
            "sources": {},
            "total_subdomains": 0,
        }

        seen = set()

        # Parse JSONL output
        for line in raw_output.strip().split("\n"):
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                # Plain text subdomain
                if line and "." in line and line not in seen:
                    seen.add(line)
                    result["subdomains"].append({
                        "subdomain": line,
                        "source": "unknown"
                    })
                continue

            # JSON format
            host = data.get("host", "")
            source = data.get("source", "unknown")

            if host and host not in seen:
                seen.add(host)
                result["subdomains"].append({
                    "subdomain": host,
                    "source": source
                })

                # Track sources
                result["sources"][source] = result["sources"].get(source, 0) + 1

        result["total_subdomains"] = len(result["subdomains"])

        return result

    def enumerate(
        self,
        domain: str,
        all_sources: bool = False,
        recursive: bool = False
    ) -> "ToolResult":
        """Run subdomain enumeration."""
        return self.run(domain, options={
            "all_sources": all_sources,
            "recursive": recursive
        })
