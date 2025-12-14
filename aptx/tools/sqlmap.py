"""
APT-X SQLMap Wrapper
====================

Python wrapper for SQLMap SQL injection testing tool.
Implements safe mode restrictions for responsible testing.
"""

import json
import re
from typing import Any, Dict, List, Optional

from aptx.tools.base import ToolWrapper


class SqlmapWrapper(ToolWrapper):
    """
    SQLMap SQL injection tool wrapper.

    Includes safe mode restrictions to prevent destructive testing.
    """

    name = "sqlmap"
    description = "Automatic SQL injection detection and exploitation"
    install_hint = "apt install sqlmap"
    default_timeout = 600  # 10 minutes

    # Risk levels
    RISK_LEVELS = {
        "safe": 1,      # Only basic tests
        "normal": 2,    # Default behavior
        "aggressive": 3  # All tests including OR-based
    }

    # Safe mode restrictions
    SAFE_MODE_ARGS = [
        "--batch",           # Non-interactive
        "--risk=1",          # Low risk
        "--level=1",         # Basic tests
        "--no-cast",         # Avoid potential issues
        "--skip-waf",        # Don't test WAF bypass
        "--tamper=",         # No tampering (cleared)
    ]

    # Dangerous options blocked in safe mode
    DANGEROUS_OPTIONS = [
        "--os-shell", "--os-pwn", "--os-bof", "--os-smbrelay",
        "--priv-esc", "--file-read", "--file-write", "--file-dest",
        "--reg-read", "--reg-add", "--reg-del", "--reg-key",
        "--sql-shell", "--sql-query", "--sql-file",
        "--dump-all", "--dump", "--dump-format",
        "--forms", "--crawl",  # Can be aggressive
    ]

    def __init__(self, safe_mode: bool = True, **kwargs):
        """
        Initialize SQLMap wrapper.

        Args:
            safe_mode: Enable safe mode restrictions (default: True)
        """
        super().__init__(**kwargs)
        self.safe_mode = safe_mode

    def build_command(
        self,
        target: str,
        options: Optional[Dict] = None
    ) -> List[str]:
        """
        Build SQLMap command.

        Options:
            parameter: Parameter to test
            method: HTTP method (GET/POST)
            data: POST data
            cookie: Cookie string
            headers: Custom headers
            level: Testing level (1-5)
            risk: Risk level (1-3)
            dbms: Database type hint
            technique: Injection techniques
            prefix: Injection prefix
            suffix: Injection suffix
            tamper: Tamper scripts
            timeout: Request timeout
            threads: Number of threads
            batch: Non-interactive mode
            extra_args: Additional arguments (checked in safe mode)
        """
        options = options or {}

        cmd = [self.binary_path]

        # Target URL
        cmd.extend(["-u", target])

        # Output format
        cmd.extend(["--output-dir=/tmp/sqlmap"])

        # Safe mode enforcement
        if self.safe_mode:
            cmd.extend([
                "--batch",
                "--risk=1",
                "--level=2",
            ])
            # Block dangerous operations
            self._validate_safe_options(options)
        else:
            # Even in non-safe mode, always batch
            cmd.append("--batch")

        # Parameter
        if "parameter" in options:
            cmd.extend(["-p", options["parameter"]])

        # Method and data
        if "method" in options and options["method"].upper() == "POST":
            if "data" in options:
                cmd.extend(["--data", options["data"]])

        # Cookie
        if "cookie" in options:
            cmd.extend(["--cookie", options["cookie"]])

        # Headers
        if "headers" in options:
            for header in options["headers"]:
                cmd.extend(["-H", header])

        # Level (capped in safe mode)
        level = options.get("level", 2)
        if self.safe_mode:
            level = min(level, 2)
        cmd.extend(["--level", str(level)])

        # Risk (capped in safe mode)
        risk = options.get("risk", 1)
        if self.safe_mode:
            risk = min(risk, 1)
        cmd.extend(["--risk", str(risk)])

        # DBMS hint
        if "dbms" in options:
            cmd.extend(["--dbms", options["dbms"]])

        # Techniques
        if "technique" in options:
            cmd.extend(["--technique", options["technique"]])

        # Prefix/Suffix
        if "prefix" in options:
            cmd.extend(["--prefix", options["prefix"]])
        if "suffix" in options:
            cmd.extend(["--suffix", options["suffix"]])

        # Tamper (blocked in safe mode)
        if "tamper" in options and not self.safe_mode:
            tamper = options["tamper"]
            if isinstance(tamper, list):
                tamper = ",".join(tamper)
            cmd.extend(["--tamper", tamper])

        # Timeout
        if "timeout" in options:
            cmd.extend(["--timeout", str(options["timeout"])])

        # Threads
        threads = options.get("threads", 1)
        cmd.extend(["--threads", str(threads)])

        # Verbosity
        cmd.append("-v")
        cmd.append("2")  # Verbose but not too much

        # String/Regex matching for detection
        if "string" in options:
            cmd.extend(["--string", options["string"]])
        if "regexp" in options:
            cmd.extend(["--regexp", options["regexp"]])

        # User agent
        if "user_agent" in options:
            cmd.extend(["--user-agent", options["user_agent"]])
        else:
            cmd.extend(["--random-agent"])

        # Extra arguments (validated in safe mode)
        if "extra_args" in options:
            extra = options["extra_args"]
            if isinstance(extra, str):
                extra = extra.split()
            if self.safe_mode:
                extra = self._filter_dangerous_args(extra)
            cmd.extend(extra)

        return cmd

    def _validate_safe_options(self, options: Dict) -> None:
        """Validate options don't contain dangerous commands."""
        extra_args = options.get("extra_args", [])
        if isinstance(extra_args, str):
            extra_args = extra_args.split()

        for arg in extra_args:
            for dangerous in self.DANGEROUS_OPTIONS:
                if arg.startswith(dangerous):
                    raise ValueError(
                        f"Option '{arg}' blocked in safe mode. "
                        "Set safe_mode=False to enable (not recommended)."
                    )

    def _filter_dangerous_args(self, args: List[str]) -> List[str]:
        """Remove dangerous arguments."""
        safe_args = []
        for arg in args:
            is_dangerous = False
            for dangerous in self.DANGEROUS_OPTIONS:
                if arg.startswith(dangerous):
                    is_dangerous = True
                    self.logger.warning(f"Blocked dangerous argument: {arg}")
                    break
            if not is_dangerous:
                safe_args.append(arg)
        return safe_args

    def parse_output(
        self,
        raw_output: str,
        target: str
    ) -> Dict[str, Any]:
        """Parse SQLMap output."""
        result = {
            "target": target,
            "vulnerable": False,
            "injection_points": [],
            "dbms": None,
            "parameters_tested": [],
            "payloads": [],
            "backend_info": {},
            "log": raw_output[:20000],
        }

        # Check for vulnerability detection
        if "is vulnerable" in raw_output.lower() or \
           "might be injectable" in raw_output.lower():
            result["vulnerable"] = True

        # Extract injection type
        injection_patterns = [
            r"Type:\s*([^\n]+)",
            r"Payload:\s*([^\n]+)",
            r"Parameter:\s*([^\n]+)",
        ]

        current_injection = {}
        for line in raw_output.split("\n"):
            line = line.strip()

            # Injection type
            type_match = re.search(r"Type:\s*(.+)", line)
            if type_match:
                if current_injection:
                    result["injection_points"].append(current_injection)
                current_injection = {"type": type_match.group(1)}

            # Title
            title_match = re.search(r"Title:\s*(.+)", line)
            if title_match and current_injection:
                current_injection["title"] = title_match.group(1)

            # Payload
            payload_match = re.search(r"Payload:\s*(.+)", line)
            if payload_match:
                payload = payload_match.group(1)
                if current_injection:
                    current_injection["payload"] = payload
                result["payloads"].append(payload)

            # Parameter
            param_match = re.search(r"Parameter:\s*(\S+)", line)
            if param_match:
                param = param_match.group(1)
                if param not in result["parameters_tested"]:
                    result["parameters_tested"].append(param)

            # DBMS detection
            dbms_match = re.search(r"back-end DBMS:\s*(.+)", line, re.I)
            if dbms_match:
                result["dbms"] = dbms_match.group(1)
                result["backend_info"]["dbms"] = dbms_match.group(1)

            # Web technology
            tech_match = re.search(r"web application technology:\s*(.+)", line, re.I)
            if tech_match:
                result["backend_info"]["technology"] = tech_match.group(1)

        # Add last injection point
        if current_injection:
            result["injection_points"].append(current_injection)

        return result

    def test(
        self,
        target: str,
        parameter: Optional[str] = None,
        method: str = "GET",
        data: Optional[str] = None
    ) -> "ToolResult":
        """Test a URL for SQL injection (safe mode)."""
        options = {"method": method}
        if parameter:
            options["parameter"] = parameter
        if data:
            options["data"] = data
        return self.run(target, options=options)

    def test_form(
        self,
        target: str,
        data: str,
        parameter: Optional[str] = None
    ) -> "ToolResult":
        """Test a POST form for SQL injection."""
        return self.test(
            target,
            parameter=parameter,
            method="POST",
            data=data
        )

    def set_safe_mode(self, enabled: bool) -> None:
        """Enable or disable safe mode."""
        self.safe_mode = enabled
        self.logger.info(f"Safe mode: {'enabled' if enabled else 'disabled'}")
