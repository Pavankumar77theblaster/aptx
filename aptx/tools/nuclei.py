"""
APT-X Nuclei Wrapper
====================

Python wrapper for ProjectDiscovery Nuclei vulnerability scanner.
"""

import json
from typing import Any, Dict, List, Optional

from aptx.tools.base import ToolWrapper


class NucleiWrapper(ToolWrapper):
    """
    Nuclei vulnerability scanner wrapper.

    Template-based vulnerability scanner for fast and customizable scanning.
    """

    name = "nuclei"
    description = "Template-based vulnerability scanner"
    install_hint = "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    default_timeout = 600  # 10 minutes

    # Severity levels
    SEVERITIES = ["info", "low", "medium", "high", "critical", "unknown"]

    def build_command(
        self,
        target: str,
        options: Optional[Dict] = None
    ) -> List[str]:
        """
        Build Nuclei command.

        Options:
            templates: List of template paths or IDs
            template_tags: Tags to filter templates
            severity: Severity levels to include
            exclude_tags: Tags to exclude
            rate_limit: Rate limit
            concurrency: Number of concurrent templates
            timeout: Request timeout
            headers: Custom headers
            extra_args: Additional arguments
        """
        options = options or {}

        cmd = [self.binary_path]

        # Target
        cmd.extend(["-u", target])

        # JSON output
        cmd.extend(["-jsonl", "-silent"])

        # Templates
        if "templates" in options:
            templates = options["templates"]
            if isinstance(templates, list):
                for t in templates:
                    cmd.extend(["-t", t])
            else:
                cmd.extend(["-t", templates])

        # Template tags
        if "template_tags" in options:
            tags = options["template_tags"]
            if isinstance(tags, list):
                tags = ",".join(tags)
            cmd.extend(["-tags", tags])

        # Severity filter
        if "severity" in options:
            severity = options["severity"]
            if isinstance(severity, list):
                severity = ",".join(severity)
            cmd.extend(["-severity", severity])

        # Exclude tags
        if "exclude_tags" in options:
            exclude = options["exclude_tags"]
            if isinstance(exclude, list):
                exclude = ",".join(exclude)
            cmd.extend(["-etags", exclude])

        # Rate limit
        if "rate_limit" in options:
            cmd.extend(["-rate-limit", str(options["rate_limit"])])

        # Concurrency
        if "concurrency" in options:
            cmd.extend(["-c", str(options["concurrency"])])

        # Timeout
        if "timeout" in options:
            cmd.extend(["-timeout", str(options["timeout"])])

        # Headers
        if "headers" in options:
            for header in options["headers"]:
                cmd.extend(["-H", header])

        # Disable automatic updates
        cmd.append("-duc")

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
        """Parse Nuclei JSON output."""
        result = {
            "target": target,
            "findings": [],
            "severity_counts": {sev: 0 for sev in self.SEVERITIES},
            "templates_matched": [],
            "total_findings": 0,
        }

        # Parse JSONL output
        for line in raw_output.strip().split("\n"):
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            # Extract finding info
            finding = {
                "template_id": data.get("template-id", ""),
                "template_name": data.get("info", {}).get("name", ""),
                "severity": data.get("info", {}).get("severity", "unknown"),
                "type": data.get("type", ""),
                "host": data.get("host", ""),
                "matched_at": data.get("matched-at", ""),
                "matcher_name": data.get("matcher-name", ""),
                "extracted_results": data.get("extracted-results", []),
                "description": data.get("info", {}).get("description", ""),
                "reference": data.get("info", {}).get("reference", []),
                "tags": data.get("info", {}).get("tags", []),
                "curl_command": data.get("curl-command", ""),
                "request": data.get("request", ""),
                "response": data.get("response", "")[:5000],  # Truncate
                "timestamp": data.get("timestamp", ""),
            }

            result["findings"].append(finding)

            # Count by severity
            severity = finding["severity"].lower()
            if severity in result["severity_counts"]:
                result["severity_counts"][severity] += 1

            # Track templates
            template_id = finding["template_id"]
            if template_id and template_id not in result["templates_matched"]:
                result["templates_matched"].append(template_id)

        result["total_findings"] = len(result["findings"])

        return result

    def scan(
        self,
        target: str,
        severity: Optional[List[str]] = None,
        tags: Optional[List[str]] = None
    ) -> "ToolResult":
        """Run vulnerability scan."""
        options = {}
        if severity:
            options["severity"] = severity
        if tags:
            options["template_tags"] = tags
        return self.run(target, options=options)

    def scan_with_templates(
        self,
        target: str,
        templates: List[str]
    ) -> "ToolResult":
        """Run scan with specific templates."""
        return self.run(target, options={"templates": templates})

    def cve_scan(self, target: str) -> "ToolResult":
        """Scan for known CVEs."""
        return self.run(target, options={"template_tags": ["cve"]})

    def exposure_scan(self, target: str) -> "ToolResult":
        """Scan for exposures and misconfigurations."""
        return self.run(target, options={
            "template_tags": ["exposure", "misconfig"],
            "severity": ["low", "medium", "high", "critical"]
        })
