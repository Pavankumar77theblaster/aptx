"""
APT-X Pipeline Stages
=====================

Complete set of pipeline stages for the penetration testing workflow.
Includes crawling, parameter discovery, vulnerability scanning, validation, and reporting.
"""

import asyncio
from datetime import datetime
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse, urljoin, parse_qs, urlencode

from aptx.core.pipeline import PipelineStage, PipelineContext, StageResult, StageStatus
from aptx.core.logger import get_logger
from aptx.core.database import get_database


class CrawlingStage(PipelineStage):
    """
    Web crawling and content discovery stage.

    Uses ffuf for directory/file discovery and basic crawling.
    """

    name = "crawling"
    description = "Crawl web servers for content discovery"
    requires = ["web_discovery"]
    produces = ["endpoints", "directories"]

    # Common paths to check
    COMMON_PATHS = [
        "robots.txt", "sitemap.xml", ".well-known/security.txt",
        "admin", "login", "api", "wp-admin", "wp-login.php",
        "administrator", "phpmyadmin", "console", "dashboard",
        ".git/HEAD", ".env", "config.php", "web.config",
        "backup", "test", "dev", "staging", "old",
    ]

    async def execute(self, context: PipelineContext) -> StageResult:
        """Execute crawling stage."""
        started = datetime.utcnow()

        try:
            from aptx.tools.ffuf import FfufWrapper

            ffuf = FfufWrapper()
            discovered_endpoints = []
            discovered_dirs = []

            # Get web servers to crawl
            web_servers = list(context.web_servers)
            if not web_servers:
                web_servers = [f"http://{context.target}"]

            # Limit targets
            max_targets = context.config.get("crawling", {}).get("max_targets", 10)
            web_servers = web_servers[:max_targets]

            for server in web_servers:
                # Check common paths first
                common_results = await self._check_common_paths(server, context)
                discovered_endpoints.extend(common_results)

                # Use ffuf for discovery if available
                if ffuf.is_available():
                    ffuf_results = await self._run_ffuf(ffuf, server, context)
                    discovered_dirs.extend(ffuf_results.get("directories", []))
                    discovered_endpoints.extend(ffuf_results.get("endpoints", []))

                # Add to context
                for endpoint in discovered_endpoints:
                    context.add_endpoint(endpoint)

            completed = datetime.utcnow()

            return StageResult(
                stage_name=self.name,
                status=StageStatus.COMPLETED,
                started_at=started,
                completed_at=completed,
                duration_seconds=(completed - started).total_seconds(),
                data={
                    "servers_crawled": len(web_servers),
                    "endpoints_found": len(discovered_endpoints),
                    "directories_found": len(discovered_dirs),
                    "endpoints": discovered_endpoints[:100],  # Limit for output
                },
                findings_count=len(discovered_endpoints)
            )

        except Exception as e:
            self.logger.error(f"Crawling failed: {e}")
            return StageResult(
                stage_name=self.name,
                status=StageStatus.FAILED,
                started_at=started,
                completed_at=datetime.utcnow(),
                error=str(e)
            )

    async def _check_common_paths(
        self,
        server: str,
        context: PipelineContext
    ) -> List[str]:
        """Check common paths on server."""
        import httpx

        found = []

        async with httpx.AsyncClient(timeout=10.0, verify=False, follow_redirects=True) as client:
            for path in self.COMMON_PATHS:
                if context.rate_limiter:
                    await context.rate_limiter.acquire_async()

                url = urljoin(server, path)
                try:
                    response = await client.head(url)
                    if response.status_code in [200, 301, 302, 403]:
                        found.append(url)
                        self.logger.debug(f"Found: {url} ({response.status_code})")
                except Exception:
                    pass

        return found

    async def _run_ffuf(
        self,
        ffuf: "FfufWrapper",
        server: str,
        context: PipelineContext
    ) -> Dict[str, List]:
        """Run ffuf for content discovery."""
        results = {"directories": [], "endpoints": []}

        options = {
            "threads": 20 if context.safe_mode else 50,
            "rate": context.config.get("crawling", {}).get("rate", 100),
            "filter_status": "404",
            "match_status": "200,204,301,302,307,401,403",
        }

        try:
            result = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: ffuf.run(server, options)
            )

            if result.success:
                for item in result.parsed_data.get("results", []):
                    url = item.get("url", "")
                    if url:
                        if item.get("status") in [301, 302, 307]:
                            results["directories"].append(url)
                        else:
                            results["endpoints"].append(url)
        except Exception as e:
            self.logger.warning(f"ffuf failed: {e}")

        return results


class ParameterDiscoveryStage(PipelineStage):
    """
    Parameter discovery stage.

    Identifies URL parameters, form fields, and API endpoints.
    """

    name = "parameter_discovery"
    description = "Discover URL parameters and form fields"
    requires = ["crawling"]
    produces = ["parameters"]

    # Common parameter names
    COMMON_PARAMS = [
        "id", "page", "search", "q", "query", "s", "keyword",
        "user", "username", "name", "email", "password",
        "file", "path", "dir", "url", "redirect", "next", "return",
        "action", "cmd", "command", "exec", "do",
        "cat", "category", "type", "sort", "order", "filter",
        "limit", "offset", "start", "count", "num",
        "token", "key", "api_key", "auth", "session",
        "callback", "jsonp", "format", "output",
        "lang", "language", "locale", "debug", "test",
    ]

    async def execute(self, context: PipelineContext) -> StageResult:
        """Execute parameter discovery stage."""
        started = datetime.utcnow()

        try:
            import httpx
            from bs4 import BeautifulSoup

            discovered_params: Dict[str, List[Dict]] = {}

            endpoints = list(context.endpoints)
            if not endpoints:
                # Use web servers if no endpoints discovered
                endpoints = list(context.web_servers)

            # Limit endpoints to scan
            max_endpoints = context.config.get("param_discovery", {}).get("max_endpoints", 50)
            endpoints = endpoints[:max_endpoints]

            async with httpx.AsyncClient(timeout=15.0, verify=False, follow_redirects=True) as client:
                for endpoint in endpoints:
                    if context.rate_limiter:
                        await context.rate_limiter.acquire_async()

                    params = await self._discover_params(client, endpoint)
                    if params:
                        discovered_params[endpoint] = params
                        context.parameters[endpoint] = params

            # Also test for common parameters
            reflected_params = await self._test_common_params(endpoints[:10], context)

            completed = datetime.utcnow()

            total_params = sum(len(p) for p in discovered_params.values())

            return StageResult(
                stage_name=self.name,
                status=StageStatus.COMPLETED,
                started_at=started,
                completed_at=completed,
                duration_seconds=(completed - started).total_seconds(),
                data={
                    "endpoints_analyzed": len(endpoints),
                    "total_parameters": total_params,
                    "parameters": discovered_params,
                    "reflected_params": reflected_params,
                },
                findings_count=total_params
            )

        except Exception as e:
            self.logger.error(f"Parameter discovery failed: {e}")
            return StageResult(
                stage_name=self.name,
                status=StageStatus.FAILED,
                started_at=started,
                completed_at=datetime.utcnow(),
                error=str(e)
            )

    async def _discover_params(
        self,
        client: "httpx.AsyncClient",
        endpoint: str
    ) -> List[Dict]:
        """Discover parameters from endpoint."""
        params = []

        try:
            # Parse URL for existing parameters
            parsed = urlparse(endpoint)
            if parsed.query:
                for param, values in parse_qs(parsed.query).items():
                    params.append({
                        "name": param,
                        "source": "url",
                        "value": values[0] if values else "",
                    })

            # Fetch page and parse forms
            response = await client.get(endpoint)

            if response.status_code == 200 and "text/html" in response.headers.get("content-type", ""):
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(response.text, "html.parser")

                # Find form inputs
                for form in soup.find_all("form"):
                    form_action = form.get("action", "")
                    form_method = form.get("method", "GET").upper()

                    for inp in form.find_all(["input", "select", "textarea"]):
                        name = inp.get("name")
                        if name:
                            params.append({
                                "name": name,
                                "source": "form",
                                "type": inp.get("type", "text"),
                                "form_action": form_action,
                                "method": form_method,
                            })

                # Find links with parameters
                for link in soup.find_all("a", href=True):
                    href = link["href"]
                    if "?" in href:
                        link_parsed = urlparse(href)
                        for param in parse_qs(link_parsed.query).keys():
                            if not any(p["name"] == param for p in params):
                                params.append({
                                    "name": param,
                                    "source": "link",
                                })

        except Exception as e:
            self.logger.debug(f"Error discovering params for {endpoint}: {e}")

        return params

    async def _test_common_params(
        self,
        endpoints: List[str],
        context: PipelineContext
    ) -> Dict[str, List[str]]:
        """Test for common reflected parameters."""
        import httpx

        reflected = {}
        test_value = "aptxtest123"

        async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
            for endpoint in endpoints:
                if context.rate_limiter:
                    await context.rate_limiter.acquire_async()

                found_params = []

                for param in self.COMMON_PARAMS[:20]:  # Test top 20
                    try:
                        url = f"{endpoint}?{param}={test_value}"
                        response = await client.get(url)

                        if test_value in response.text:
                            found_params.append(param)
                            self.logger.debug(f"Reflected param: {param} at {endpoint}")
                    except Exception:
                        pass

                if found_params:
                    reflected[endpoint] = found_params

        return reflected


class VulnerabilityScanStage(PipelineStage):
    """
    Vulnerability scanning stage.

    Runs all enabled vulnerability scanners against discovered targets.
    """

    name = "vulnerability_scan"
    description = "Scan for vulnerabilities using multiple scanners"
    requires = ["parameter_discovery"]
    produces = ["findings"]

    async def execute(self, context: PipelineContext) -> StageResult:
        """Execute vulnerability scanning stage."""
        started = datetime.utcnow()

        try:
            from aptx.vulnerabilities.base import ScanTarget

            # Import all scanners
            scanners = await self._load_scanners(context)

            all_findings = []
            scanner_results = {}

            # Build targets from discovered parameters
            targets = self._build_targets(context)

            self.logger.info(f"Scanning {len(targets)} targets with {len(scanners)} scanners")

            for scanner_name, scanner in scanners.items():
                self.logger.info(f"Running {scanner_name} scanner...")

                scanner_findings = []

                for target in targets:
                    try:
                        findings = await scanner.scan(target)
                        scanner_findings.extend(findings)

                        # Add findings to context
                        for finding in findings:
                            finding_dict = finding.to_dict()
                            context.add_finding(finding_dict)
                            all_findings.append(finding_dict)

                    except Exception as e:
                        self.logger.warning(f"Scanner {scanner_name} error on {target.url}: {e}")

                scanner_results[scanner_name] = {
                    "findings": len(scanner_findings),
                    "targets_scanned": len(targets),
                }

                # Close scanner client
                if hasattr(scanner, 'close'):
                    await scanner.close()

            # Save findings to database
            db = get_database()
            for finding in all_findings:
                db.add_finding(context.scan_id, finding)

            completed = datetime.utcnow()

            return StageResult(
                stage_name=self.name,
                status=StageStatus.COMPLETED,
                started_at=started,
                completed_at=completed,
                duration_seconds=(completed - started).total_seconds(),
                data={
                    "scanners_run": len(scanners),
                    "targets_scanned": len(targets),
                    "total_findings": len(all_findings),
                    "scanner_results": scanner_results,
                    "findings_by_severity": self._count_by_severity(all_findings),
                },
                findings_count=len(all_findings)
            )

        except Exception as e:
            self.logger.error(f"Vulnerability scan failed: {e}")
            return StageResult(
                stage_name=self.name,
                status=StageStatus.FAILED,
                started_at=started,
                completed_at=datetime.utcnow(),
                error=str(e)
            )

    async def _load_scanners(self, context: PipelineContext) -> Dict:
        """Load enabled vulnerability scanners."""
        scanners = {}

        # Get enabled scanners from config
        vuln_config = context.config.get("vulnerabilities", {})
        enabled = vuln_config.get("enabled", [
            "sqli", "xss", "idor", "ssrf", "open_redirect", "command_injection"
        ])

        scanner_classes = {
            "sqli": ("aptx.vulnerabilities.sqli", "SQLiScanner"),
            "xss": ("aptx.vulnerabilities.xss", "XSSScanner"),
            "idor": ("aptx.vulnerabilities.idor", "IDORScanner"),
            "ssrf": ("aptx.vulnerabilities.ssrf", "SSRFScanner"),
            "open_redirect": ("aptx.vulnerabilities.open_redirect", "OpenRedirectScanner"),
            "command_injection": ("aptx.vulnerabilities.command_injection", "CommandInjectionScanner"),
            "auth_bypass": ("aptx.vulnerabilities.auth_bypass", "AuthBypassScanner"),
            "file_upload": ("aptx.vulnerabilities.file_upload", "FileUploadScanner"),
            "misconfig": ("aptx.vulnerabilities.misconfig", "MisconfigScanner"),
        }

        for scanner_name in enabled:
            if scanner_name in scanner_classes:
                module_path, class_name = scanner_classes[scanner_name]
                try:
                    import importlib
                    module = importlib.import_module(module_path)
                    scanner_class = getattr(module, class_name)
                    scanners[scanner_name] = scanner_class(
                        config=vuln_config.get(scanner_name, {}),
                        scope=context.scope,
                        rate_limiter=context.rate_limiter,
                        safe_mode=context.safe_mode
                    )
                except Exception as e:
                    self.logger.warning(f"Failed to load {scanner_name}: {e}")

        return scanners

    def _build_targets(self, context: PipelineContext) -> List["ScanTarget"]:
        """Build scan targets from context."""
        from aptx.vulnerabilities.base import ScanTarget

        targets = []

        # Create targets from discovered parameters
        for endpoint, params in context.parameters.items():
            if params:
                param_dict = {p["name"]: "test" for p in params if "name" in p}
                if param_dict:
                    targets.append(ScanTarget(
                        url=endpoint,
                        method="GET",
                        parameters=param_dict
                    ))

                # Also add POST targets for form parameters
                form_params = [p for p in params if p.get("source") == "form"]
                if form_params:
                    targets.append(ScanTarget(
                        url=endpoint,
                        method="POST",
                        parameters={p["name"]: "test" for p in form_params}
                    ))

        # Add basic targets from endpoints if no params found
        if not targets:
            for endpoint in list(context.endpoints)[:20]:
                targets.append(ScanTarget(url=endpoint))

            for server in list(context.web_servers)[:10]:
                targets.append(ScanTarget(url=server))

        return targets[:100]  # Limit

    def _count_by_severity(self, findings: List[Dict]) -> Dict[str, int]:
        """Count findings by severity."""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", "info").lower()
            if sev in counts:
                counts[sev] += 1
        return counts


class ValidationStage(PipelineStage):
    """
    Finding validation stage.

    Validates findings with safe proof-of-concept testing.
    """

    name = "validation"
    description = "Validate findings with safe PoC testing"
    requires = ["vulnerability_scan"]
    produces = ["validated_findings"]

    async def execute(self, context: PipelineContext) -> StageResult:
        """Execute validation stage."""
        started = datetime.utcnow()

        try:
            validated_count = 0
            false_positive_count = 0

            # Load scanners for validation
            scanners = {}
            scanner_classes = {
                "sqli": ("aptx.vulnerabilities.sqli", "SQLiScanner"),
                "xss": ("aptx.vulnerabilities.xss", "XSSScanner"),
            }

            for scanner_name, (module_path, class_name) in scanner_classes.items():
                try:
                    import importlib
                    module = importlib.import_module(module_path)
                    scanner_class = getattr(module, class_name)
                    scanners[scanner_name] = scanner_class(
                        scope=context.scope,
                        rate_limiter=context.rate_limiter,
                        safe_mode=True  # Always safe mode for validation
                    )
                except Exception:
                    pass

            # Validate high-confidence findings
            for i, finding in enumerate(context.findings):
                if finding.get("confidence", 0) >= 50:
                    vuln_type = finding.get("vuln_type", "")
                    scanner = scanners.get(vuln_type)

                    if scanner and hasattr(scanner, 'validate'):
                        try:
                            from aptx.vulnerabilities.base import Finding as FindingClass
                            finding_obj = FindingClass(**{
                                k: v for k, v in finding.items()
                                if k in FindingClass.__dataclass_fields__
                            })

                            is_valid, note = await scanner.validate(finding_obj)

                            context.findings[i]["validated"] = is_valid
                            context.findings[i]["validation_note"] = note

                            if is_valid:
                                validated_count += 1
                            else:
                                false_positive_count += 1

                        except Exception as e:
                            self.logger.debug(f"Validation error: {e}")

            # Close scanner clients
            for scanner in scanners.values():
                if hasattr(scanner, 'close'):
                    await scanner.close()

            completed = datetime.utcnow()

            return StageResult(
                stage_name=self.name,
                status=StageStatus.COMPLETED,
                started_at=started,
                completed_at=completed,
                duration_seconds=(completed - started).total_seconds(),
                data={
                    "total_findings": len(context.findings),
                    "validated": validated_count,
                    "false_positives": false_positive_count,
                    "unvalidated": len(context.findings) - validated_count - false_positive_count,
                },
                findings_count=validated_count
            )

        except Exception as e:
            self.logger.error(f"Validation failed: {e}")
            return StageResult(
                stage_name=self.name,
                status=StageStatus.FAILED,
                started_at=started,
                completed_at=datetime.utcnow(),
                error=str(e)
            )


class ReportingStage(PipelineStage):
    """
    Report generation stage.

    Generates penetration test reports in multiple formats.
    """

    name = "reporting"
    description = "Generate penetration test report"
    requires = ["validation"]
    produces = ["report"]

    async def execute(self, context: PipelineContext) -> StageResult:
        """Execute reporting stage."""
        started = datetime.utcnow()

        try:
            from aptx.reporting.generator import ReportGenerator

            generator = ReportGenerator()
            db = get_database()

            # Get scan data
            scan = db.get_scan(context.scan_id)
            if not scan:
                scan = {
                    "id": context.scan_id,
                    "target": context.target,
                    "started_at": context.started_at.isoformat() if context.started_at else "",
                }

            # Get report format from config
            report_config = context.config.get("reporting", {})
            formats = report_config.get("formats", ["html", "json"])
            output_dir = report_config.get("output_dir", "reports")

            reports_generated = []

            for fmt in formats:
                try:
                    output_path = f"{output_dir}/report_{context.scan_id[:8]}.{fmt}"
                    report_path = generator.generate(
                        scan=scan,
                        findings=context.findings,
                        format=fmt,
                        output_path=output_path
                    )
                    reports_generated.append(report_path)
                    self.logger.info(f"Generated {fmt.upper()} report: {report_path}")
                except Exception as e:
                    self.logger.warning(f"Failed to generate {fmt} report: {e}")

            completed = datetime.utcnow()

            return StageResult(
                stage_name=self.name,
                status=StageStatus.COMPLETED,
                started_at=started,
                completed_at=completed,
                duration_seconds=(completed - started).total_seconds(),
                data={
                    "reports_generated": reports_generated,
                    "formats": formats,
                },
                findings_count=len(context.findings),
                artifacts=reports_generated
            )

        except Exception as e:
            self.logger.error(f"Reporting failed: {e}")
            return StageResult(
                stage_name=self.name,
                status=StageStatus.FAILED,
                started_at=started,
                completed_at=datetime.utcnow(),
                error=str(e)
            )


def register_all_stages(pipeline: "Pipeline") -> None:
    """
    Register all pipeline stages.

    Args:
        pipeline: Pipeline instance to register stages with
    """
    from aptx.core.pipeline import TargetIntakeStage, ScopeValidationStage
    from aptx.recon.subdomain import SubdomainEnumStage
    from aptx.recon.port_scan import PortScanStage
    from aptx.recon.web_discovery import WebDiscoveryStage

    # Core stages
    pipeline.register_stage(TargetIntakeStage)
    pipeline.register_stage(ScopeValidationStage)

    # Recon stages
    pipeline.register_stage(SubdomainEnumStage)
    pipeline.register_stage(PortScanStage)
    pipeline.register_stage(WebDiscoveryStage)

    # Discovery stages
    pipeline.register_stage(CrawlingStage)
    pipeline.register_stage(ParameterDiscoveryStage)

    # Scanning stages
    pipeline.register_stage(VulnerabilityScanStage)
    pipeline.register_stage(ValidationStage)

    # Reporting
    pipeline.register_stage(ReportingStage)
