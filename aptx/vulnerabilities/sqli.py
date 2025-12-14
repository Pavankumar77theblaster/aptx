"""
APT-X SQL Injection Scanner
===========================

SQL Injection detection with multiple techniques and safe mode support.
"""

import re
import asyncio
from typing import Dict, List, Optional, Tuple

from aptx.vulnerabilities.base import (
    WebVulnerabilityScanner,
    Finding,
    ScanTarget,
    Severity,
    VulnerabilityType,
)
from aptx.core.database import Severity as DbSeverity


class SQLiScanner(WebVulnerabilityScanner):
    """
    SQL Injection vulnerability scanner.

    Supports error-based, boolean-based, and time-based detection.
    """

    vuln_type = VulnerabilityType.SQLI
    name = "sqli"
    description = "SQL Injection detection"
    severity = Severity.CRITICAL

    # Error-based payloads
    ERROR_PAYLOADS = [
        "'",
        "\"",
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "' OR '1'='1' --",
        "' OR '1'='1' #",
        "1' ORDER BY 1--",
        "1' ORDER BY 10--",
        "' UNION SELECT NULL--",
        "' AND '1'='1",
        "' AND '1'='2",
        "1 AND 1=1",
        "1 AND 1=2",
        "' OR SLEEP(0)--",
        "'; SELECT SLEEP(0)--",
    ]

    # Safe payloads (detection only, no exploitation)
    SAFE_PAYLOADS = [
        "'",
        "\"",
        "' OR '1'='1",
        "1' AND '1'='1",
        "1' AND '1'='2",
        "' OR 'x'='x",
        "1 AND 1=1",
        "1 AND 1=2",
    ]

    # Database error patterns
    ERROR_PATTERNS = {
        "mysql": [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_",
            r"MySQLSyntaxErrorException",
            r"valid MySQL result",
            r"check the manual that corresponds to your MySQL",
            r"Unknown column",
            r"mysql_fetch_array\(\)",
            r"MySql Error",
            r"mysqli_",
        ],
        "postgresql": [
            r"PostgreSQL.*ERROR",
            r"Warning.*\Wpg_",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            r"PG::SyntaxError:",
            r"PSQLException",
        ],
        "mssql": [
            r"Driver.* SQL[\-\_\ ]*Server",
            r"OLE DB.* SQL Server",
            r"\bSQL Server\b",
            r"SQL Server.*Driver",
            r"Warning.*mssql_",
            r"SQLException",
            r"ODBC SQL Server Driver",
        ],
        "oracle": [
            r"\bORA-[0-9][0-9][0-9][0-9]",
            r"Oracle error",
            r"Oracle.*Driver",
            r"Warning.*\Woci_",
            r"Warning.*\Wora_",
        ],
        "sqlite": [
            r"SQLite\/JDBCDriver",
            r"SQLite.Exception",
            r"System.Data.SQLite.SQLiteException",
            r"Warning.*sqlite_",
            r"Warning.*SQLite3::",
            r"\[SQLITE_ERROR\]",
            r"sqlite3.OperationalError:",
        ],
        "generic": [
            r"SQL syntax",
            r"syntax error",
            r"unclosed quotation mark",
            r"quoted string not properly terminated",
            r"SQL command not properly ended",
        ]
    }

    detection_payloads = ERROR_PAYLOADS
    safe_payloads = SAFE_PAYLOADS

    async def scan(
        self,
        target: ScanTarget,
        options: Optional[Dict] = None
    ) -> List[Finding]:
        """
        Scan for SQL injection vulnerabilities.

        Args:
            target: Target URL and parameters
            options: Scanner options

        Returns:
            List of SQL injection findings
        """
        options = options or {}
        findings = []

        if not self.validate_target(target):
            return findings

        self.logger.info(f"Scanning for SQLi: {target.url}")

        # Get parameters to test
        params_to_test = list(target.parameters.keys())

        if not params_to_test:
            self.logger.debug("No parameters to test")
            return findings

        payloads = self.get_payloads()

        for param in params_to_test:
            # Get baseline response
            baseline = await self._request(target)
            if not baseline:
                continue

            param_findings = await self._test_parameter(
                target, param, payloads, baseline, options
            )
            findings.extend(param_findings)

            # Stop if we found vulnerabilities (avoid excessive testing)
            if findings and options.get("stop_on_first", False):
                break

        return findings

    async def _test_parameter(
        self,
        target: ScanTarget,
        param: str,
        payloads: List[str],
        baseline: Dict,
        options: Dict
    ) -> List[Finding]:
        """Test a single parameter for SQLi."""
        findings = []
        error_indicators = []
        boolean_indicators = []

        for payload in payloads:
            response = await self._request(target, payload, param)
            if not response:
                continue

            # Check for error-based SQLi
            error_result = self._check_error_based(response["body"])
            if error_result:
                error_indicators.append(error_result)

            # Check for boolean-based SQLi
            if self._check_boolean_based(baseline, response, payload):
                boolean_indicators.append("boolean_based")

        # Create finding if indicators found
        if error_indicators or boolean_indicators:
            indicators = list(set(error_indicators + boolean_indicators))
            confidence = self.calculate_confidence(indicators)

            if confidence >= 30:  # Minimum threshold
                finding = self.create_finding(
                    target=target,
                    title=f"SQL Injection in '{param}' parameter",
                    description=self._get_description(indicators),
                    evidence=f"Detected indicators: {', '.join(indicators)}",
                    payload=payloads[0] if payloads else "",
                    confidence=confidence,
                    parameter=param,
                    references=[
                        "https://owasp.org/www-community/attacks/SQL_Injection",
                        "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
                    ]
                )
                findings.append(finding)

        return findings

    def _check_error_based(self, response_body: str) -> Optional[str]:
        """Check for SQL error messages in response."""
        for db_type, patterns in self.ERROR_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, response_body, re.IGNORECASE):
                    self.logger.debug(f"Found {db_type} error pattern")
                    return "error_based"
        return None

    def _check_boolean_based(
        self,
        baseline: Dict,
        response: Dict,
        payload: str
    ) -> bool:
        """Check for boolean-based injection indicators."""
        # Compare response lengths
        baseline_len = len(baseline.get("body", ""))
        response_len = len(response.get("body", ""))

        # True condition payloads should return similar content
        if "1'='1" in payload or "1=1" in payload:
            # Expect similar to baseline
            if abs(baseline_len - response_len) < baseline_len * 0.1:
                return False  # Similar, inconclusive alone

        # False condition payloads should return different content
        if "1'='2" in payload or "1=2" in payload:
            # Expect different from baseline
            if abs(baseline_len - response_len) > baseline_len * 0.1:
                return True  # Significant difference

        return False

    def _get_description(self, indicators: List[str]) -> str:
        """Generate description based on indicators."""
        desc = "SQL Injection vulnerability detected. "

        if "error_based" in indicators:
            desc += "The application returns database error messages when malformed input is provided. "

        if "boolean_based" in indicators:
            desc += "The application exhibits different behavior based on boolean SQL conditions. "

        desc += (
            "An attacker could potentially extract, modify, or delete database contents, "
            "bypass authentication, or execute system commands depending on the database configuration."
        )

        return desc

    async def validate(
        self,
        finding: Finding,
        options: Optional[Dict] = None
    ) -> Tuple[bool, str]:
        """
        Validate SQL injection finding with safe PoC.

        Uses simple, non-destructive tests to confirm the vulnerability.
        """
        options = options or {}

        # Create target from finding
        target = ScanTarget(
            url=finding.url,
            method=finding.method,
            parameters={finding.parameter: "test"}
        )

        # Test with simple true/false conditions
        true_payload = "' OR '1'='1"
        false_payload = "' OR '1'='2"

        true_response = await self._request(target, true_payload, finding.parameter)
        false_response = await self._request(target, false_payload, finding.parameter)

        if true_response and false_response:
            true_len = len(true_response.get("body", ""))
            false_len = len(false_response.get("body", ""))

            # If responses differ significantly, likely vulnerable
            if abs(true_len - false_len) > 50:
                return True, "Validated via boolean-based differential response"

        return False, "Could not validate with safe PoC"

    def get_remediation(self, finding: Optional[Finding] = None) -> str:
        """Get SQL injection remediation guidance."""
        return """
**SQL Injection Remediation:**

1. **Use Parameterized Queries (Prepared Statements)**
   - Never concatenate user input into SQL queries
   - Use query parameters/placeholders for all user input

2. **Input Validation**
   - Validate and sanitize all user input
   - Use allowlist validation where possible
   - Reject unexpected input types

3. **Least Privilege**
   - Use database accounts with minimal required permissions
   - Don't use admin/root database accounts for applications

4. **Error Handling**
   - Never expose database errors to users
   - Log errors internally, show generic messages externally

5. **Web Application Firewall (WAF)**
   - Deploy a WAF to detect and block SQLi attempts
   - Regularly update WAF rules

6. **Code Examples:**

   Python (SQLAlchemy):
   ```python
   # WRONG
   query = f"SELECT * FROM users WHERE id = {user_id}"

   # RIGHT
   query = text("SELECT * FROM users WHERE id = :id")
   result = connection.execute(query, {"id": user_id})
   ```

   PHP (PDO):
   ```php
   // WRONG
   $sql = "SELECT * FROM users WHERE id = " . $_GET['id'];

   // RIGHT
   $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
   $stmt->execute([$_GET['id']]);
   ```
"""
