"""
APT-X ffuf Wrapper
==================

Python wrapper for ffuf (Fuzz Faster U Fool) web fuzzer.
"""

import json
from typing import Any, Dict, List, Optional

from aptx.tools.base import ToolWrapper


class FfufWrapper(ToolWrapper):
    """
    ffuf web fuzzer wrapper.

    Fast web fuzzer for directory/file discovery and parameter fuzzing.
    """

    name = "ffuf"
    description = "Fast web fuzzer for content discovery"
    install_hint = "go install github.com/ffuf/ffuf/v2@latest"
    default_timeout = 600  # 10 minutes

    def build_command(
        self,
        target: str,
        options: Optional[Dict] = None
    ) -> List[str]:
        """
        Build ffuf command.

        Options:
            wordlist: Path to wordlist file
            extensions: File extensions to append
            method: HTTP method
            headers: Custom headers
            data: POST data
            filter_status: Status codes to filter out
            match_status: Status codes to match
            filter_size: Response sizes to filter
            threads: Number of threads
            rate: Requests per second
            recursion: Enable recursion
            timeout: Request timeout
            extra_args: Additional arguments
        """
        options = options or {}

        cmd = [self.binary_path]

        # URL with FUZZ keyword
        if "FUZZ" not in target:
            target = target.rstrip("/") + "/FUZZ"
        cmd.extend(["-u", target])

        # JSON output
        cmd.extend(["-of", "json", "-o", "-"])

        # Silent mode
        cmd.append("-s")

        # Wordlist
        wordlist = options.get("wordlist", "/usr/share/seclists/Discovery/Web-Content/common.txt")
        cmd.extend(["-w", wordlist])

        # Extensions
        if "extensions" in options:
            extensions = options["extensions"]
            if isinstance(extensions, list):
                extensions = ",".join(extensions)
            cmd.extend(["-e", extensions])

        # HTTP method
        if "method" in options:
            cmd.extend(["-X", options["method"]])

        # Headers
        if "headers" in options:
            for header in options["headers"]:
                cmd.extend(["-H", header])

        # POST data
        if "data" in options:
            cmd.extend(["-d", options["data"]])

        # Filter status codes
        if "filter_status" in options:
            codes = options["filter_status"]
            if isinstance(codes, list):
                codes = ",".join(map(str, codes))
            cmd.extend(["-fc", codes])

        # Match status codes
        if "match_status" in options:
            codes = options["match_status"]
            if isinstance(codes, list):
                codes = ",".join(map(str, codes))
            cmd.extend(["-mc", codes])
        else:
            # Default: match common success codes
            cmd.extend(["-mc", "200,204,301,302,307,401,403,405,500"])

        # Filter by size
        if "filter_size" in options:
            sizes = options["filter_size"]
            if isinstance(sizes, list):
                sizes = ",".join(map(str, sizes))
            cmd.extend(["-fs", sizes])

        # Threads
        threads = options.get("threads", 40)
        cmd.extend(["-t", str(threads)])

        # Rate limit
        if "rate" in options:
            cmd.extend(["-rate", str(options["rate"])])

        # Recursion
        if options.get("recursion", False):
            cmd.append("-recursion")
            if "recursion_depth" in options:
                cmd.extend(["-recursion-depth", str(options["recursion_depth"])])

        # Timeout
        if "timeout" in options:
            cmd.extend(["-timeout", str(options["timeout"])])

        # Auto-calibrate
        if options.get("auto_calibrate", False):
            cmd.append("-ac")

        # Extra arguments
        if "extra_args" in options:
            extra = options["extra_args"]
            if isinstance(extra, str):
                cmd.extend(extra.split())
            elif isinstance(extra, list):
                cmd.extend(extra)

        return cmd

    def _uses_output_file(self) -> bool:
        return True

    def _inject_output_file(self, cmd: List[str], path: str) -> List[str]:
        # Replace stdout output with file
        new_cmd = []
        skip_next = False
        for i, arg in enumerate(cmd):
            if skip_next:
                skip_next = False
                continue
            if arg == "-o" and i + 1 < len(cmd) and cmd[i + 1] == "-":
                new_cmd.extend(["-o", path])
                skip_next = True
            else:
                new_cmd.append(arg)
        return new_cmd

    def parse_output(
        self,
        raw_output: str,
        target: str
    ) -> Dict[str, Any]:
        """Parse ffuf JSON output."""
        result = {
            "target": target,
            "results": [],
            "status_codes": {},
            "total_results": 0,
            "config": {},
        }

        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError:
            # Try to parse as plain text
            return self._parse_text_output(raw_output, target)

        # Parse config
        result["config"] = {
            "url": data.get("config", {}).get("url", ""),
            "wordlist": data.get("config", {}).get("wordlist", ""),
            "method": data.get("config", {}).get("method", "GET"),
        }

        # Parse results
        for item in data.get("results", []):
            found = {
                "url": item.get("url", ""),
                "input": item.get("input", {}).get("FUZZ", ""),
                "status": item.get("status"),
                "length": item.get("length"),
                "words": item.get("words"),
                "lines": item.get("lines"),
                "content_type": item.get("content-type", ""),
                "redirectlocation": item.get("redirectlocation", ""),
                "duration": item.get("duration"),
            }
            result["results"].append(found)

            # Count status codes
            status = str(found["status"])
            result["status_codes"][status] = result["status_codes"].get(status, 0) + 1

        result["total_results"] = len(result["results"])

        return result

    def _parse_text_output(
        self,
        output: str,
        target: str
    ) -> Dict[str, Any]:
        """Fallback parser for text output."""
        result = {
            "target": target,
            "results": [],
            "raw_text": output[:10000],
            "total_results": 0,
        }

        # Try to extract URLs from output
        import re
        url_pattern = r'https?://[^\s<>"\']+|/[^\s<>"\']*'
        for match in re.finditer(url_pattern, output):
            result["results"].append({"url": match.group(0)})

        result["total_results"] = len(result["results"])
        return result

    def fuzz_dirs(
        self,
        target: str,
        wordlist: Optional[str] = None,
        extensions: Optional[List[str]] = None
    ) -> "ToolResult":
        """Directory fuzzing."""
        options = {}
        if wordlist:
            options["wordlist"] = wordlist
        if extensions:
            options["extensions"] = extensions
        return self.run(target, options=options)

    def fuzz_params(
        self,
        target: str,
        param_wordlist: str,
        method: str = "GET"
    ) -> "ToolResult":
        """Parameter fuzzing."""
        # Add FUZZ to parameter
        if "?" not in target:
            target += "?FUZZ=test"
        return self.run(target, options={
            "wordlist": param_wordlist,
            "method": method
        })

    def fuzz_subdomains(
        self,
        domain: str,
        wordlist: str
    ) -> "ToolResult":
        """Subdomain fuzzing via vhost."""
        target = f"http://{domain}"
        return self.run(target, options={
            "wordlist": wordlist,
            "headers": [f"Host: FUZZ.{domain}"]
        })
