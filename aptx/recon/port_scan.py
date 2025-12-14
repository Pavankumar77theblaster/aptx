"""
APT-X Port Scanner
==================

Port scanning module using Nmap with safe mode support.
"""

import asyncio
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from aptx.recon.base import ReconModule, ReconResult, ReconType, ReconPipelineStage
from aptx.core.pipeline import PipelineContext, StageResult, StageStatus
from aptx.tools.nmap import NmapWrapper


class PortScanner(ReconModule):
    """
    Port scanning module.

    Uses Nmap for comprehensive port scanning with safe mode restrictions.
    """

    recon_type = ReconType.PORT_SCAN
    name = "port_scan"
    description = "Scan ports using Nmap"

    # Safe mode port ranges
    SAFE_PORTS = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5432,5900,8080,8443"
    DEFAULT_PORTS = "1-1000"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        # Initialize Nmap
        self.nmap = NmapWrapper()
        self.available = self.nmap.is_available()

        if not self.available:
            self.logger.warning("Nmap not available")

    async def execute(
        self,
        target: str,
        options: Optional[Dict] = None
    ) -> ReconResult:
        """
        Scan ports on target.

        Args:
            target: Target IP or hostname
            options: Options including:
                - ports: Port specification
                - scan_type: Scan type preset
                - safe_mode: Enable safe mode
                - version_detection: Detect service versions
                - timeout: Scan timeout

        Returns:
            ReconResult with open ports
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
                error="Nmap not available"
            )

        # Configure scan options
        safe_mode = options.get("safe_mode", True)
        nmap_options = self._build_nmap_options(options, safe_mode)

        self.logger.info(f"Port scanning {target} with options: {nmap_options}")

        await self.rate_limit(target)

        try:
            # Run Nmap
            result = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.nmap.run(target, nmap_options)
            )

            completed = datetime.utcnow()

            if result.success:
                # Process results
                hosts = result.parsed_data.get("hosts", [])
                open_ports = []
                services = []

                for host in hosts:
                    host_ip = host.get("ip", target)
                    for port in host.get("ports", []):
                        if port.get("state") == "open":
                            port_info = {
                                "host": host_ip,
                                "port": port.get("port"),
                                "protocol": port.get("protocol", "tcp"),
                                "service": port.get("service"),
                                "version": port.get("version"),
                                "state": "open"
                            }
                            open_ports.append(port_info)

                            if port.get("service"):
                                services.append({
                                    "host": host_ip,
                                    "port": port.get("port"),
                                    "service": port.get("service"),
                                    "version": port.get("version")
                                })

                result_data = {
                    "hosts": hosts,
                    "open_ports": open_ports,
                    "services": services,
                    "total_open_ports": len(open_ports),
                    "total_hosts": len(hosts),
                    "scan_info": result.parsed_data.get("scan_info", {}),
                }

                self.logger.info(f"Found {len(open_ports)} open ports on {target}")

                return ReconResult(
                    recon_type=self.recon_type,
                    target=target,
                    success=True,
                    started_at=started,
                    completed_at=completed,
                    duration_seconds=(completed - started).total_seconds(),
                    data=result_data,
                    items_found=len(open_ports)
                )

            else:
                return ReconResult(
                    recon_type=self.recon_type,
                    target=target,
                    success=False,
                    started_at=started,
                    completed_at=completed,
                    duration_seconds=(completed - started).total_seconds(),
                    error=result.error
                )

        except Exception as e:
            self.logger.error(f"Port scan failed: {e}")
            return ReconResult(
                recon_type=self.recon_type,
                target=target,
                success=False,
                started_at=started,
                completed_at=datetime.utcnow(),
                error=str(e)
            )

    def _build_nmap_options(
        self,
        options: Dict,
        safe_mode: bool
    ) -> Dict:
        """Build Nmap options with safe mode restrictions."""
        nmap_options = {}

        # Scan type
        if safe_mode:
            nmap_options["scan_type"] = "safe"
            nmap_options["ports"] = options.get("ports", self.SAFE_PORTS)
            nmap_options["timing"] = 3  # Normal timing
        else:
            nmap_options["scan_type"] = options.get("scan_type", "default")
            nmap_options["ports"] = options.get("ports", self.DEFAULT_PORTS)

        # Version detection
        nmap_options["version_detection"] = options.get("version_detection", True)

        # OS detection (requires root, skip in safe mode)
        if not safe_mode and options.get("os_detection", False):
            nmap_options["os_detection"] = True

        # Scripts
        if not safe_mode and "scripts" in options:
            nmap_options["scripts"] = options["scripts"]

        return nmap_options


class PortScanStage(ReconPipelineStage):
    """Pipeline stage for port scanning."""

    name = "port_scan"
    description = "Scan ports using Nmap"
    requires = ["target_intake", "scope_validation"]
    produces = ["open_ports", "services"]
    module_class = PortScanner

    async def execute(self, context: PipelineContext) -> StageResult:
        """Execute port scanning stage."""
        started = datetime.utcnow()

        try:
            module = self._create_module(context)

            # Get targets (main target + discovered hosts)
            targets = [context.target]

            # Optionally scan discovered subdomains
            config = context.config.get("recon", {}).get("port_scan", {})
            if config.get("scan_subdomains", False):
                # Limit to avoid excessive scanning
                max_targets = config.get("max_targets", 10)
                for subdomain in list(context.subdomains)[:max_targets - 1]:
                    if subdomain not in targets:
                        targets.append(subdomain)

            all_ports = []
            all_services = []

            for target in targets:
                options = {
                    "safe_mode": context.safe_mode,
                    "ports": config.get("ports", PortScanner.SAFE_PORTS if context.safe_mode else "1-1000"),
                }

                result = await module.execute(target, options)

                if result.success:
                    # Store open ports
                    context.open_ports[target] = [
                        p["port"] for p in result.data.get("open_ports", [])
                    ]

                    all_ports.extend(result.data.get("open_ports", []))
                    all_services.extend(result.data.get("services", []))

                    # Identify web servers for next stages
                    for port_info in result.data.get("open_ports", []):
                        port = port_info.get("port")
                        service = port_info.get("service", "")

                        # Detect HTTP services
                        if port in [80, 8080, 8000, 8888] or "http" in service.lower():
                            context.add_web_server(f"http://{target}:{port}")
                        elif port in [443, 8443] or "https" in service.lower() or "ssl" in service.lower():
                            context.add_web_server(f"https://{target}:{port}")

            completed = datetime.utcnow()

            return StageResult(
                stage_name=self.name,
                status=StageStatus.COMPLETED,
                started_at=started,
                completed_at=completed,
                duration_seconds=(completed - started).total_seconds(),
                data={
                    "targets_scanned": len(targets),
                    "open_ports": all_ports,
                    "services": all_services,
                    "web_servers_found": len(context.web_servers)
                },
                findings_count=len(all_ports)
            )

        except Exception as e:
            self.logger.error(f"Port scan failed: {e}")
            return StageResult(
                stage_name=self.name,
                status=StageStatus.FAILED,
                started_at=started,
                completed_at=datetime.utcnow(),
                error=str(e)
            )
