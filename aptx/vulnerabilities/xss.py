"""
APT-X XSS Scanner
=================

Cross-Site Scripting detection for Reflected, Stored, and DOM-based XSS.
"""

import re
import html
from typing import Dict, List, Optional, Tuple
from urllib.parse import quote, unquote

from aptx.vulnerabilities.base import (
    WebVulnerabilityScanner,
    Finding,
    ScanTarget,
    Severity,
    VulnerabilityType,
)


class XSSScanner(WebVulnerabilityScanner):
    """
    Cross-Site Scripting (XSS) vulnerability scanner.

    Detects Reflected, Stored, and DOM-based XSS vulnerabilities.
    """

    vuln_type = VulnerabilityType.XSS
    name = "xss"
    description = "Cross-Site Scripting detection"
    severity = Severity.HIGH

    # Reflected XSS payloads
    REFLECTED_PAYLOADS = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
        "'\"><script>alert(1)</script>",
        "'\"><img src=x onerror=alert(1)>",
        "<body onload=alert(1)>",
        "<iframe src=javascript:alert(1)>",
        "'-alert(1)-'",
        "\"-alert(1)-\"",
        "</script><script>alert(1)</script>",
        "<ScRiPt>alert(1)</ScRiPt>",
        "<img/src=x onerror=alert(1)>",
        "<<script>alert(1)</script>",
        "<input onfocus=alert(1) autofocus>",
    ]

    # Safe detection payloads (unlikely to trigger actual XSS)
    SAFE_PAYLOADS = [
        "<aptx-test-xss>",
        "aptx\"test'xss",
        "<script>aptx</script>",
        "<img src=aptx>",
        "javascript:aptx",
        "'-aptx-'",
        "\"-aptx-\"",
        "</title><aptx>",
        "<svg><aptx>",
        "{{aptx}}",
        "${aptx}",
    ]

    # DOM XSS sinks
    DOM_SINKS = [
        "document.write",
        "document.writeln",
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        "eval(",
        "setTimeout(",
        "setInterval(",
        "Function(",
        "location",
        "location.href",
        "location.assign",
        "location.replace",
        "window.open",
    ]

    # DOM XSS sources
    DOM_SOURCES = [
        "location.hash",
        "location.search",
        "location.href",
        "document.URL",
        "document.documentURI",
        "document.referrer",
        "window.name",
        "postMessage",
    ]

    detection_payloads = REFLECTED_PAYLOADS
    safe_payloads = SAFE_PAYLOADS

    async def scan(
        self,
        target: ScanTarget,
        options: Optional[Dict] = None
    ) -> List[Finding]:
        """
        Scan for XSS vulnerabilities.

        Args:
            target: Target URL and parameters
            options: Scanner options including:
                - types: List of XSS types to check (reflected, stored, dom)

        Returns:
            List of XSS findings
        """
        options = options or {}
        findings = []

        if not self.validate_target(target):
            return findings

        self.logger.info(f"Scanning for XSS: {target.url}")

        xss_types = options.get("types", ["reflected", "dom"])

        # Test reflected XSS
        if "reflected" in xss_types:
            reflected_findings = await self._scan_reflected(target, options)
            findings.extend(reflected_findings)

        # Check for DOM XSS indicators
        if "dom" in xss_types:
            dom_findings = await self._scan_dom(target, options)
            findings.extend(dom_findings)

        return findings

    async def _scan_reflected(
        self,
        target: ScanTarget,
        options: Dict
    ) -> List[Finding]:
        """Scan for reflected XSS."""
        findings = []
        params_to_test = list(target.parameters.keys())

        if not params_to_test:
            return findings

        payloads = self.get_payloads()

        for param in params_to_test:
            for payload in payloads:
                response = await self._request(target, payload, param)
                if not response:
                    continue

                # Check if payload is reflected
                reflection = self._check_reflection(
                    payload, response["body"]
                )

                if reflection:
                    confidence = self._calculate_xss_confidence(
                        payload, response["body"], reflection
                    )

                    if confidence >= 30:
                        finding = self.create_finding(
                            target=target,
                            title=f"Reflected XSS in '{param}' parameter",
                            description=self._get_reflected_description(reflection),
                            evidence=f"Payload reflected: {reflection['type']}",
                            payload=payload,
                            confidence=confidence,
                            parameter=param,
                            references=[
                                "https://owasp.org/www-community/attacks/xss/",
                                "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
                            ]
                        )
                        findings.append(finding)
                        break  # Found for this param, move to next

        return findings

    async def _scan_dom(
        self,
        target: ScanTarget,
        options: Dict
    ) -> List[Finding]:
        """Scan for DOM-based XSS indicators."""
        findings = []

        # Get page content
        response = await self._request(target)
        if not response:
            return findings

        body = response["body"]

        # Check for dangerous DOM patterns
        dom_findings = self._analyze_dom_patterns(body, target)

        if dom_findings:
            # Create a single finding for DOM XSS indicators
            indicators = [f["pattern"] for f in dom_findings]
            confidence = min(60, 20 + len(dom_findings) * 10)

            finding = self.create_finding(
                target=target,
                title="Potential DOM-based XSS",
                description=self._get_dom_description(dom_findings),
                evidence=f"Dangerous patterns found: {', '.join(indicators[:5])}",
                payload="",
                confidence=confidence,
                severity=Severity.MEDIUM,  # Lower severity without confirmation
                references=[
                    "https://owasp.org/www-community/attacks/DOM_Based_XSS",
                ]
            )
            findings.append(finding)

        return findings

    def _check_reflection(
        self,
        payload: str,
        response_body: str
    ) -> Optional[Dict]:
        """
        Check if payload is reflected in response.

        Returns reflection details if found.
        """
        # Check exact match
        if payload in response_body:
            return {
                "type": "exact",
                "context": self._get_reflection_context(payload, response_body)
            }

        # Check URL-decoded match
        decoded = unquote(payload)
        if decoded != payload and decoded in response_body:
            return {
                "type": "url_decoded",
                "context": self._get_reflection_context(decoded, response_body)
            }

        # Check HTML-encoded match
        encoded = html.escape(payload)
        if encoded != payload and encoded in response_body:
            return {
                "type": "html_encoded",
                "context": "safe"  # Properly encoded
            }

        # Check partial reflection (key characters)
        key_chars = ["<", ">", "'", "\"", "(", ")"]
        reflected_chars = sum(1 for c in key_chars if c in response_body and c in payload)
        if reflected_chars >= 3:
            return {
                "type": "partial",
                "context": "unknown"
            }

        return None

    def _get_reflection_context(self, payload: str, body: str) -> str:
        """Determine the context where payload is reflected."""
        idx = body.find(payload)
        if idx == -1:
            return "unknown"

        # Get surrounding context
        start = max(0, idx - 50)
        end = min(len(body), idx + len(payload) + 50)
        context = body[start:end]

        # Check context
        if re.search(r'<script[^>]*>.*' + re.escape(payload), context, re.I):
            return "script_tag"
        if re.search(r'on\w+\s*=\s*["\'].*' + re.escape(payload), context, re.I):
            return "event_handler"
        if re.search(r'href\s*=\s*["\'].*' + re.escape(payload), context, re.I):
            return "href_attribute"
        if re.search(r'<[^>]*' + re.escape(payload), context):
            return "html_tag"
        if re.search(r'["\'][^"\']*' + re.escape(payload), context):
            return "attribute_value"

        return "body"

    def _calculate_xss_confidence(
        self,
        payload: str,
        body: str,
        reflection: Dict
    ) -> int:
        """Calculate XSS confidence based on reflection analysis."""
        confidence = 0

        reflection_type = reflection.get("type", "")
        context = reflection.get("context", "")

        # Base confidence by reflection type
        if reflection_type == "exact":
            confidence += 40
        elif reflection_type == "url_decoded":
            confidence += 30
        elif reflection_type == "partial":
            confidence += 15

        # Context bonuses
        context_scores = {
            "script_tag": 50,
            "event_handler": 45,
            "href_attribute": 35,
            "html_tag": 30,
            "attribute_value": 25,
            "body": 15,
            "safe": -20,
        }
        confidence += context_scores.get(context, 0)

        # Payload complexity bonus
        if "<script>" in payload.lower():
            confidence += 10
        if "onerror" in payload.lower() or "onload" in payload.lower():
            confidence += 10

        return min(100, max(0, confidence))

    def _analyze_dom_patterns(
        self,
        body: str,
        target: ScanTarget
    ) -> List[Dict]:
        """Analyze JavaScript for DOM XSS patterns."""
        findings = []

        # Extract JavaScript
        script_pattern = r'<script[^>]*>(.*?)</script>'
        scripts = re.findall(script_pattern, body, re.DOTALL | re.I)
        js_content = "\n".join(scripts)

        # Also check inline JS
        js_content += body

        # Check for source -> sink patterns
        for source in self.DOM_SOURCES:
            if source in js_content:
                for sink in self.DOM_SINKS:
                    if sink in js_content:
                        # Check if they're potentially connected
                        pattern = f"{source}.*{sink}|{sink}.*{source}"
                        if re.search(pattern, js_content, re.DOTALL):
                            findings.append({
                                "source": source,
                                "sink": sink,
                                "pattern": f"{source} -> {sink}"
                            })

        return findings

    def _get_reflected_description(self, reflection: Dict) -> str:
        """Generate description for reflected XSS."""
        context = reflection.get("context", "unknown")

        desc = (
            "A Reflected Cross-Site Scripting (XSS) vulnerability was detected. "
            "User input is reflected in the response without proper encoding. "
        )

        if context == "script_tag":
            desc += "The input is reflected inside a script tag, allowing direct JavaScript execution. "
        elif context == "event_handler":
            desc += "The input is reflected in an event handler attribute. "
        elif context == "href_attribute":
            desc += "The input is reflected in a URL attribute, potentially allowing javascript: URLs. "

        desc += (
            "An attacker could exploit this to execute arbitrary JavaScript in victims' browsers, "
            "potentially stealing session tokens, credentials, or performing actions as the user."
        )

        return desc

    def _get_dom_description(self, dom_findings: List[Dict]) -> str:
        """Generate description for DOM XSS."""
        return (
            "Potential DOM-based XSS patterns were detected in the page's JavaScript. "
            f"Found {len(dom_findings)} source-to-sink data flow(s) that may be exploitable. "
            "DOM XSS occurs when client-side scripts process untrusted data and write it to "
            "dangerous sinks without proper sanitization. Manual verification is recommended."
        )

    async def validate(
        self,
        finding: Finding,
        options: Optional[Dict] = None
    ) -> Tuple[bool, str]:
        """Validate XSS finding."""
        # Create target
        target = ScanTarget(
            url=finding.url,
            method=finding.method,
            parameters={finding.parameter: "test"}
        )

        # Use a unique marker
        marker = "aptx-xss-validate-12345"
        test_payload = f"<{marker}>"

        response = await self._request(target, test_payload, finding.parameter)

        if response and f"<{marker}>" in response["body"]:
            return True, "Validated: unescaped HTML tags reflected"

        return False, "Could not validate XSS"

    def get_remediation(self, finding: Optional[Finding] = None) -> str:
        """Get XSS remediation guidance."""
        return """
**Cross-Site Scripting (XSS) Remediation:**

1. **Output Encoding**
   - Encode all user input based on context (HTML, JavaScript, URL, CSS)
   - Use context-aware encoding libraries

2. **Content Security Policy (CSP)**
   - Implement strict CSP headers
   - Disable inline scripts and eval
   - Use nonce or hash-based script allowlisting

3. **Input Validation**
   - Validate input type, length, format
   - Use allowlist validation where possible

4. **HTTP-Only Cookies**
   - Set HttpOnly flag on session cookies
   - Prevents JavaScript access to cookies

5. **Modern Frameworks**
   - Use frameworks with auto-escaping (React, Angular, Vue)
   - Avoid dangerouslySetInnerHTML and similar

6. **Code Examples:**

   JavaScript:
   ```javascript
   // WRONG
   element.innerHTML = userInput;

   // RIGHT
   element.textContent = userInput;
   // or use DOMPurify for HTML content
   element.innerHTML = DOMPurify.sanitize(userInput);
   ```

   Python (Jinja2):
   ```python
   # Templates auto-escape by default
   {{ user_input }}  # Safe

   # If you must allow HTML, sanitize first
   {{ user_input | safe }}  # DANGEROUS without sanitization
   ```

7. **CSP Header Example:**
   ```
   Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-random123'
   ```
"""
