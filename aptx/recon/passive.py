"""
APT-X Passive Reconnaissance
============================

Passive reconnaissance using public data sources.
No direct interaction with the target.
"""

import asyncio
import socket
import dns.resolver
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from aptx.recon.base import ReconModule, ReconResult, ReconType, ReconPipelineStage
from aptx.core.pipeline import PipelineContext, StageResult, StageStatus


class PassiveRecon(ReconModule):
    """
    Passive reconnaissance module.

    Gathers information without direct target interaction.
    """

    recon_type = ReconType.PASSIVE
    name = "passive"
    description = "Passive information gathering"

    # DNS record types to query
    DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 10

    async def execute(
        self,
        target: str,
        options: Optional[Dict] = None
    ) -> ReconResult:
        """
        Perform passive reconnaissance.

        Args:
            target: Target domain
            options: Options including:
                - dns_lookup: Perform DNS lookups
                - whois: Perform WHOIS lookup
                - reverse_dns: Perform reverse DNS

        Returns:
            ReconResult with gathered information
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

        self.logger.info(f"Passive reconnaissance for {target}")

        result_data = {
            "target": target,
            "dns_records": {},
            "resolved_ips": [],
            "mx_servers": [],
            "ns_servers": [],
            "txt_records": [],
            "reverse_dns": {},
        }

        try:
            # DNS lookups
            if options.get("dns_lookup", True):
                dns_results = await self._dns_lookup(target)
                result_data["dns_records"] = dns_results

                # Extract IPs
                if "A" in dns_results:
                    result_data["resolved_ips"] = dns_results["A"]
                if "AAAA" in dns_results:
                    result_data["resolved_ips"].extend(dns_results["AAAA"])

                # Extract MX servers
                if "MX" in dns_results:
                    result_data["mx_servers"] = dns_results["MX"]

                # Extract NS servers
                if "NS" in dns_results:
                    result_data["ns_servers"] = dns_results["NS"]

                # Extract TXT records
                if "TXT" in dns_results:
                    result_data["txt_records"] = dns_results["TXT"]

            # Reverse DNS
            if options.get("reverse_dns", True) and result_data["resolved_ips"]:
                for ip in result_data["resolved_ips"][:5]:  # Limit
                    hostname = await self._reverse_dns(ip)
                    if hostname:
                        result_data["reverse_dns"][ip] = hostname

            completed = datetime.utcnow()

            # Count items found
            items_found = (
                len(result_data["resolved_ips"]) +
                len(result_data["mx_servers"]) +
                len(result_data["ns_servers"]) +
                len(result_data["txt_records"])
            )

            return ReconResult(
                recon_type=self.recon_type,
                target=target,
                success=True,
                started_at=started,
                completed_at=completed,
                duration_seconds=(completed - started).total_seconds(),
                data=result_data,
                items_found=items_found
            )

        except Exception as e:
            self.logger.error(f"Passive recon failed: {e}")
            return ReconResult(
                recon_type=self.recon_type,
                target=target,
                success=False,
                started_at=started,
                completed_at=datetime.utcnow(),
                error=str(e)
            )

    async def _dns_lookup(self, domain: str) -> Dict[str, List[str]]:
        """Perform DNS lookups for various record types."""
        results = {}

        for record_type in self.DNS_RECORD_TYPES:
            try:
                answers = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda rt=record_type: self.resolver.resolve(domain, rt)
                )

                records = []
                for rdata in answers:
                    if record_type == "MX":
                        records.append({
                            "priority": rdata.preference,
                            "host": str(rdata.exchange).rstrip(".")
                        })
                    elif record_type == "SOA":
                        records.append({
                            "mname": str(rdata.mname),
                            "rname": str(rdata.rname),
                            "serial": rdata.serial,
                        })
                    else:
                        records.append(str(rdata).strip('"'))

                if records:
                    results[record_type] = records

            except dns.resolver.NXDOMAIN:
                self.logger.debug(f"Domain not found: {domain}")
            except dns.resolver.NoAnswer:
                self.logger.debug(f"No {record_type} records for {domain}")
            except dns.resolver.NoNameservers:
                self.logger.debug(f"No nameservers for {domain}")
            except dns.exception.Timeout:
                self.logger.debug(f"DNS timeout for {domain} {record_type}")
            except Exception as e:
                self.logger.debug(f"DNS lookup error: {e}")

        return results

    async def _reverse_dns(self, ip: str) -> Optional[str]:
        """Perform reverse DNS lookup."""
        try:
            hostname = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: socket.gethostbyaddr(ip)
            )
            return hostname[0]
        except socket.herror:
            return None
        except Exception:
            return None


class PassiveReconStage(ReconPipelineStage):
    """Pipeline stage for passive reconnaissance."""

    name = "passive_recon"
    description = "Passive information gathering (DNS, WHOIS)"
    requires = ["target_intake"]
    produces = ["dns_records", "resolved_ips"]
    module_class = PassiveRecon

    async def execute(self, context: PipelineContext) -> StageResult:
        """Execute passive reconnaissance stage."""
        started = datetime.utcnow()

        try:
            module = self._create_module(context)

            options = {
                "dns_lookup": True,
                "reverse_dns": True,
            }

            result = await module.execute(context.target, options)

            if result.success:
                # Add resolved IPs as potential targets
                for ip in result.data.get("resolved_ips", []):
                    if module.validate_target(ip):
                        context.subdomains.add(ip)

            completed = datetime.utcnow()

            return StageResult(
                stage_name=self.name,
                status=StageStatus.COMPLETED if result.success else StageStatus.FAILED,
                started_at=started,
                completed_at=completed,
                duration_seconds=(completed - started).total_seconds(),
                data=result.data,
                findings_count=result.items_found,
                error=result.error
            )

        except Exception as e:
            self.logger.error(f"Passive recon failed: {e}")
            return StageResult(
                stage_name=self.name,
                status=StageStatus.FAILED,
                started_at=started,
                completed_at=datetime.utcnow(),
                error=str(e)
            )
