"""
APT-X Web Discovery
===================

Web server discovery and technology detection using httpx.
"""

import asyncio
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from aptx.recon.base import ReconModule, ReconResult, ReconType, ReconPipelineStage
from aptx.core.pipeline import PipelineContext, StageResult, StageStatus
from aptx.tools.httpx import HttpxWrapper


class WebDiscovery(ReconModule):
    """
    Web discovery module.

    Uses httpx for HTTP probing and technology detection.
    """

    recon_type = ReconType.WEB_DISCOVERY
    name = "web_discovery"
    description = "Discover web servers and detect technologies"

    # Common web ports
    DEFAULT_PORTS = [80, 443, 8080, 8443, 8000, 8888, 3000, 5000]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        # Initialize httpx
        self.httpx = HttpxWrapper()
        self.available = self.httpx.is_available()

        if not self.available:
            self.logger.warning("httpx not available")

    async def execute(
        self,
        target: str,
        options: Optional[Dict] = None
    ) -> ReconResult:
        """
        Probe target for web servers.

        Args:
            target: Target domain or IP
            options: Options including:
                - ports: Ports to probe
                - tech_detect: Enable technology detection
                - follow_redirects: Follow redirects
                - timeout: Request timeout

        Returns:
            ReconResult with web servers
        """
        started = datetime.utcnow()
        options = options or {}

        # Validate target
        if not self.validate_target(target):
            return ReconResult(
                recon_type=self.recon_type,
                target=target,
                success=False,
                started_at=started,
                completed_at=datetime.utcnow(),
                error="Target not in scope"
            )

        if not self.available:
            return ReconResult(
                recon_type=self.recon_type,
                target=target,
                success=False,
                started_at=started,
                completed_at=datetime.utcnow(),
                error="httpx not available"
            )

        # Prepare targets (add protocol prefixes)
        targets_to_probe = self._prepare_targets(target, options)

        self.logger.info(f"Probing {len(targets_to_probe)} URLs for {target}")

        await self.rate_limit(target)

        all_web_servers = []
        all_technologies = set()
        all_status_codes: Dict[str, int] = {}

        try:
            for probe_target in targets_to_probe:
                httpx_options = {
                    "tech_detect": options.get("tech_detect", True),
                    "follow_redirects": options.get("follow_redirects", True),
                    "timeout": options.get("timeout", 10),
                    "rate_limit": options.get("rate_limit", 50),
                }

                result = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda t=probe_target: self.httpx.run(t, httpx_options)
                )

                if result.success:
                    for url_info in result.parsed_data.get("urls", []):
                        # Filter by scope
                        url = url_info.get("url", "")
                        if self.scope:
                            valid, _ = self.scope.validate(url)
                            if not valid:
                                continue

                        all_web_servers.append(url_info)

                        # Collect technologies
                        for tech in url_info.get("technologies", []):
                            all_technologies.add(tech)

                        # Count status codes
                        status = str(url_info.get("status_code", "unknown"))
                        all_status_codes[status] = all_status_codes.get(status, 0) + 1

            completed = datetime.utcnow()

            # Deduplicate servers by URL
            seen_urls = set()
            unique_servers = []
            for server in all_web_servers:
                url = server.get("url", "")
                if url not in seen_urls:
                    seen_urls.add(url)
                    unique_servers.append(server)

            result_data = {
                "web_servers": unique_servers,
                "technologies": sorted(list(all_technologies)),
                "status_codes": all_status_codes,
                "total_servers": len(unique_servers),
                "total_technologies": len(all_technologies),
            }

            self.logger.info(
                f"Found {len(unique_servers)} web servers with {len(all_technologies)} technologies"
            )

            return ReconResult(
                recon_type=self.recon_type,
                target=target,
                success=True,
                started_at=started,
                completed_at=completed,
                duration_seconds=(completed - started).total_seconds(),
                data=result_data,
                items_found=len(unique_servers)
            )

        except Exception as e:
            self.logger.error(f"Web discovery failed: {e}")
            return ReconResult(
                recon_type=self.recon_type,
                target=target,
                success=False,
                started_at=started,
                completed_at=datetime.utcnow(),
                error=str(e)
            )

    def _prepare_targets(
        self,
        target: str,
        options: Dict
    ) -> List[str]:
        """Prepare list of URLs to probe."""
        targets = []

        # If already has protocol, use as-is
        if target.startswith(("http://", "https://")):
            return [target]

        # Get ports to probe
        ports = options.get("ports", self.DEFAULT_PORTS)
        if isinstance(ports, str):
            ports = [int(p.strip()) for p in ports.split(",")]

        # Generate URLs for each port
        for port in ports:
            if port in [443, 8443]:
                targets.append(f"https://{target}:{port}")
            elif port == 80:
                targets.append(f"http://{target}")
            elif port == 443:
                targets.append(f"https://{target}")
            else:
                targets.append(f"http://{target}:{port}")

        return targets


class WebDiscoveryStage(ReconPipelineStage):
    """Pipeline stage for web discovery."""

    name = "web_discovery"
    description = "Discover web servers and technologies"
    requires = ["target_intake"]
    produces = ["web_servers", "technologies"]
    module_class = WebDiscovery

    async def execute(self, context: PipelineContext) -> StageResult:
        """Execute web discovery stage."""
        started = datetime.utcnow()

        try:
            module = self._create_module(context)

            # Get targets to probe
            targets = set()

            # Add main target
            targets.add(context.target)

            # Add discovered subdomains
            targets.update(context.subdomains)

            # Add from port scan (web ports)
            for host, ports in context.open_ports.items():
                for port in ports:
                    if port in WebDiscovery.DEFAULT_PORTS:
                        targets.add(host)

            # Limit targets
            max_targets = context.config.get("recon", {}).get(
                "web_discovery", {}
            ).get("max_targets", 50)
            targets = list(targets)[:max_targets]

            all_servers = []
            all_technologies = set()

            for target in targets:
                options = {
                    "tech_detect": True,
                    "follow_redirects": True,
                    "ports": context.config.get("recon", {}).get(
                        "web_discovery", {}
                    ).get("ports", WebDiscovery.DEFAULT_PORTS),
                }

                result = await module.execute(target, options)

                if result.success:
                    for server in result.data.get("web_servers", []):
                        url = server.get("url", "")
                        if url:
                            context.add_web_server(url)
                            all_servers.append(server)

                        for tech in server.get("technologies", []):
                            all_technologies.add(tech)

            completed = datetime.utcnow()

            return StageResult(
                stage_name=self.name,
                status=StageStatus.COMPLETED,
                started_at=started,
                completed_at=completed,
                duration_seconds=(completed - started).total_seconds(),
                data={
                    "targets_probed": len(targets),
                    "web_servers": all_servers,
                    "technologies": sorted(list(all_technologies)),
                    "total_servers": len(all_servers),
                },
                findings_count=len(all_servers)
            )

        except Exception as e:
            self.logger.error(f"Web discovery failed: {e}")
            return StageResult(
                stage_name=self.name,
                status=StageStatus.FAILED,
                started_at=started,
                completed_at=datetime.utcnow(),
                error=str(e)
            )
